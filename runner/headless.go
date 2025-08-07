package runner

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/launcher/flags"
	"github.com/go-rod/rod/lib/proto"
	"github.com/pkg/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	osutils "github.com/projectdiscovery/utils/os"
)

// MustDisableSandbox determines if the current os and user needs sandbox mode disabled
func MustDisableSandbox() bool {
	// linux with root user needs "--no-sandbox" option
	// https://github.com/chromium/chromium/blob/c4d3c31083a2e1481253ff2d24298a1dfe19c754/chrome/test/chromedriver/client/chromedriver.py#L209
	return osutils.IsLinux() && os.Geteuid() == 0
}

type Browser struct {
	tempDir    string
	engine     *rod.Browser
	proxyPort  int
	proxyClose func()
	// TODO: Remove the Chrome PID kill code in favor of using Leakless(true).
	// This change will be made if there are no complaints about zombie Chrome processes.
	// Reference: https://github.com/projectdiscovery/httpx/pull/1426
	// pids    map[int32]struct{}
}

func NewBrowser(proxy string, useLocal bool, optionalArgs map[string]string) (*Browser, error) {
	dataStore, err := os.MkdirTemp("", "nuclei-*")
	if err != nil {
		return nil, errors.Wrap(err, "could not create temporary directory")
	}

	// pids := processutil.FindProcesses(processutil.IsChromeProcess)

	chromeLauncher := launcher.New().
		Leakless(true).
		Set("disable-gpu", "true").
		Set("ignore-certificate-errors", "true").
		Set("ignore-certificate-errors", "1").
		Set("disable-crash-reporter", "true").
		Set("disable-notifications", "true").
		Set("hide-scrollbars", "true").
		Set("window-size", fmt.Sprintf("%d,%d", 1080, 1920)).
		Set("mute-audio", "true").
		Set("incognito", "true").
		Delete("use-mock-keychain").
		Headless(true).
		UserDataDir(dataStore)

	if MustDisableSandbox() {
		chromeLauncher = chromeLauncher.NoSandbox(true)
	}

	executablePath, err := os.Executable()
	if err != nil {
		return nil, err
	}

	// if musl is used, most likely we are on alpine linux which is not supported by go-rod, so we fallback to default chrome
	useMusl, _ := fileutil.UseMusl(executablePath)
	if useLocal || useMusl {
		if chromePath, hasChrome := launcher.LookPath(); hasChrome {
			chromeLauncher.Bin(chromePath)
		} else {
			return nil, errors.New("the chrome browser is not installed")
		}
	}

	if proxy != "" {
		chromeLauncher = chromeLauncher.Proxy(proxy)
	}

	for k, v := range optionalArgs {
		chromeLauncher.Set(flags.Flag(k), v)
	}

	launcherURL, err := chromeLauncher.Launch()
	if err != nil {
		return nil, err
	}

	browser := rod.New().ControlURL(launcherURL)
	if browserErr := browser.Connect(); browserErr != nil {
		return nil, browserErr
	}

	engine := &Browser{
		tempDir: dataStore,
		engine:  browser,
		// pids:    pids,
	}
	return engine, nil
}

func (b *Browser) ScreenshotWithBody(url string, timeout time.Duration, idle time.Duration, headers []string, fullPage bool) ([]byte, string, error) {
	return b.screenshotWithBodyAndHostRules(url, timeout, idle, headers, fullPage, "")
}

func (b *Browser) ScreenshotWithBodyAndHostRules(url string, timeout time.Duration, idle time.Duration, headers []string, fullPage bool, hostResolverRules string) ([]byte, string, error) {
	return b.screenshotWithBodyAndHostRules(url, timeout, idle, headers, fullPage, hostResolverRules)
}

func (b *Browser) screenshotWithBodyAndHostRules(url string, timeout time.Duration, idle time.Duration, headers []string, fullPage bool, hostResolverRules string) ([]byte, string, error) {
	var page *rod.Page
	var err error
	var vhostBrowser *rod.Browser
	
	// Use MITM proxy browser if host resolver rules are provided
	if hostResolverRules != "" {
		vhostBrowser, err = b.createVhostBrowser(hostResolverRules)
		if err != nil {
			return nil, "", errors.Wrap(err, "failed to create vhost browser")
		}
		if vhostBrowser != nil {
			defer vhostBrowser.Close()
			page, err = vhostBrowser.Page(proto.TargetCreateTarget{})
			fmt.Printf("DEBUG: Created MITM vhost browser for rules: %s\n", hostResolverRules)
		} else {
			// Fallback to regular browser if no rules to apply
			page, err = b.engine.Page(proto.TargetCreateTarget{})
			fmt.Printf("DEBUG: No vhost rules to apply, using regular browser\n")
		}
	} else {
		// Use regular browser
		page, err = b.engine.Page(proto.TargetCreateTarget{})
		fmt.Printf("DEBUG: Using regular browser (no host resolver rules)\n")
	}
	
	if err != nil {
		return nil, "", err
	}
	defer page.Close()
	
	for _, header := range headers {
		headerParts := strings.SplitN(header, ":", 2)
		if len(headerParts) != 2 {
			continue
		}
		key := strings.TrimSpace(headerParts[0])
		value := strings.TrimSpace(headerParts[1])
		_, _ = page.SetExtraHeaders([]string{key, value})
	}

	page = page.Timeout(timeout)

	if err := page.Navigate(url); err != nil {
		return nil, "", err
	}

	page.Timeout(5 * time.Second).WaitNavigation(proto.PageLifecycleEventNameFirstMeaningfulPaint)()

	if err := page.WaitLoad(); err != nil {
		return nil, "", err
	}
	
	// Increase idle timeout for MITM proxy scenarios due to additional network latency
	adjustedIdle := idle
	if hostResolverRules != "" {
		// For vhost scenarios with MITM proxy, use longer idle time to ensure all resources load
		adjustedIdle = idle * 3 // Triple the idle time
		if adjustedIdle < 3*time.Second {
			adjustedIdle = 3 * time.Second // Minimum 3 seconds for proxy scenarios
		}
		fmt.Printf("DEBUG: Using extended idle timeout for MITM proxy: %v\n", adjustedIdle)
	}
	
	_ = page.WaitIdle(adjustedIdle)

	screenshot, err := page.Screenshot(fullPage, &proto.PageCaptureScreenshot{})
	if err != nil {
		return nil, "", err
	}

	body, err := page.HTML()
	if err != nil {
		return screenshot, "", err
	}

	return screenshot, body, nil
}

// CreateVhostBrowser creates a temporary browser with host resolver rules pointing to MITM proxy
func (b *Browser) createVhostBrowser(hostResolverRules string) (*rod.Browser, error) {
	// Start MITM proxy first
	if b.proxyPort == 0 {
		if err := b.startVhostProxy(); err != nil {
			return nil, err
		}
		time.Sleep(200 * time.Millisecond)
	}
	
	// Set up mappings in the proxy
	if err := b.setupVhostMapping(hostResolverRules); err != nil {
		return nil, err
	}

	// Parse rules to build Chrome host-resolver-rules that redirect to localhost proxy
	chromeHostRules := ""
	
	rules := strings.Split(hostResolverRules, ",")
	for _, rule := range rules {
		rule = strings.TrimSpace(rule)
		
		if strings.HasPrefix(rule, "MAP ") {
			// MAP directive: hostname->IP mapping
			// Format: "MAP hostname IP:port"
			parts := strings.Fields(rule)
			if len(parts) >= 3 {
				hostname := parts[1]
				// Redirect hostname to localhost proxy instead of target IP
				if chromeHostRules != "" {
					chromeHostRules += ","
				}
				chromeHostRules += fmt.Sprintf("MAP %s 127.0.0.1:%d", hostname, b.proxyPort)
			}
		}
	}
	
	if chromeHostRules == "" {
		return nil, nil // No rules to apply
	}

	// Create temporary data directory
	tempDir, err := os.MkdirTemp("", "httpx-vhost-*")
	if err != nil {
		return nil, err
	}

	// Create new launcher with host resolver rules pointing to MITM proxy
	chromeLauncher := launcher.New().
		Leakless(true).
		Set("disable-gpu", "true").
		Set("ignore-certificate-errors", "true").
		Set("ignore-certificate-errors-spki-list", "true").
		Set("ignore-ssl-errors", "true").
		Set("disable-crash-reporter", "true").
		Set("disable-notifications", "true").
		Set("hide-scrollbars", "true").
		Set("window-size", fmt.Sprintf("%d,%d", 1080, 1920)).
		Set("mute-audio", "true").
		Set("incognito", "true").
		Set("host-resolver-rules", chromeHostRules).
		Delete("use-mock-keychain").
		Headless(true).
		UserDataDir(tempDir)

	if MustDisableSandbox() {
		chromeLauncher = chromeLauncher.NoSandbox(true)
	}

	fmt.Printf("DEBUG: Creating vhost browser with Chrome rules: %s\n", chromeHostRules)

	// Launch browser
	launcherURL, err := chromeLauncher.Launch()
	if err != nil {
		os.RemoveAll(tempDir)
		return nil, err
	}

	// Connect to browser
	browser := rod.New().ControlURL(launcherURL)
	if err := browser.Connect(); err != nil {
		os.RemoveAll(tempDir)
		return nil, err
	}

	return browser, nil
}

func (b *Browser) setupVhostMapping(hostResolverRules string) error {
	// Start MITM proxy if not already running
	if b.proxyPort == 0 {
		if err := b.startVhostProxy(); err != nil {
			return err
		}
		// Wait a moment for proxy to start
		time.Sleep(200 * time.Millisecond)
	}

	// Parse host resolver rules to set up mappings
	rules := strings.Split(hostResolverRules, ",")
	for _, rule := range rules {
		rule = strings.TrimSpace(rule)
		
		if strings.HasPrefix(rule, "MAP ") {
			// MAP directive: hostname->IP mapping
			// Format: "MAP hostname IP:port"
			parts := strings.Fields(rule)
			if len(parts) >= 3 {
				hostname := parts[1]
				targetAddr := parts[2]
				vhostMappings[hostname] = targetAddr
				fmt.Printf("DEBUG: MITM proxy mapping: %s -> %s\n", hostname, targetAddr)
			}
		}
	}
	
	return nil
}

func (b *Browser) Close() {
	if b.proxyClose != nil {
		b.proxyClose()
	}
	b.engine.Close()
	os.RemoveAll(b.tempDir)
	// processutil.CloseProcesses(processutil.IsChromeProcess, b.pids)
}

// generateSelfSignedCert creates a self-signed certificate for the MITM proxy
func (b *Browser) generateSelfSignedCert() (tls.Certificate, error) {
	// Generate private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"httpx-vhost-proxy"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"localhost", "*"},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Create TLS certificate
	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	return cert, nil
}

// VhostMITMProxy creates a TLS-terminating MITM proxy for vhost screenshot support
func (b *Browser) startVhostProxy() error {
	// Generate self-signed certificate
	cert, err := b.generateSelfSignedCert()
	if err != nil {
		return err
	}

	// Find available ports for HTTP and HTTPS
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	httpPort := httpListener.Addr().(*net.TCPAddr).Port
	httpListener.Close()

	httpsListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	httpsPort := httpsListener.Addr().(*net.TCPAddr).Port
	httpsListener.Close()

	b.proxyPort = httpsPort // Store HTTPS port as primary

	// Create TLS config with our self-signed cert
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// Return our wildcard cert for any hostname
			return &cert, nil
		},
	}

	// HTTP server
	httpServer := &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", httpPort),
		Handler: http.HandlerFunc(b.handleVhostProxy),
	}

	// HTTPS server
	httpsServer := &http.Server{
		Addr:      fmt.Sprintf("127.0.0.1:%d", httpsPort),
		Handler:   http.HandlerFunc(b.handleVhostProxy),
		TLSConfig: tlsConfig,
	}

	// Store close function
	b.proxyClose = func() {
		httpServer.Close()
		httpsServer.Close()
	}

	// Start HTTP proxy server
	go func() {
		httpServer.ListenAndServe()
	}()

	// Start HTTPS proxy server
	go func() {
		httpsServer.ListenAndServeTLS("", "")
	}()

	return nil
}

// Global map to store hostname->IP mappings for the proxy
var vhostMappings = make(map[string]string)

func (b *Browser) handleVhostProxy(w http.ResponseWriter, r *http.Request) {
	hostname := r.Host
	
	// Look up target IP for this hostname
	targetIP, exists := vhostMappings[hostname]
	if !exists {
		// If no mapping, just pass through
		targetIP = hostname
	}

	// Determine target scheme
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	// Create target URL with just scheme and host - let reverse proxy handle path
	targetURL := &url.URL{
		Scheme: scheme,
		Host:   targetIP,
		// Don't set Path here - reverse proxy will append the request path automatically
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	
	// Customize transport for proper TLS SNI handling
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         hostname, // Use original hostname for TLS SNI
		},
	}

	// Modify the request to preserve original Host header
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = hostname // Preserve original hostname for vhost
		req.Header.Set("Host", hostname)
		
		// Debug output
		fmt.Printf("MITM Proxy: %s %s -> %s (SNI: %s)\n", req.Method, req.URL.String(), targetURL.String(), hostname)
	}

	proxy.ServeHTTP(w, r)
}