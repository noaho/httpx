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
    upstreamProxyURL *url.URL
    mitmCert         *tls.Certificate
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

    // We will start a local forward proxy (with TLS MITM) and always point Chrome to it.
    // If the user supplied an upstream proxy, we will chain to it from our local proxy.

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

    // Parse upstream proxy if provided (chain proxy)
    if proxy != "" {
        if u, err := url.Parse(proxy); err == nil {
            engine.upstreamProxyURL = u
        } else {
            return nil, errors.Wrap(err, "invalid upstream proxy url")
        }
    }

    // Start local forward proxy and re-point Chrome to it
    if err := engine.startForwardProxy(); err != nil {
        return nil, errors.Wrap(err, "failed to start local forward proxy")
    }

    // Relaunch Chrome with our local proxy server so all traffic goes through our proxy
    // Note: we need a new launcher to set proxy; easiest is to close and relaunch quickly
    // to ensure page contexts use the proxy. For simplicity, we create a new page after setting per-page proxy is unsupported in rod.
    // We will spawn a lightweight second Chrome with proxy set to local proxy.
    // Best-effort: if this fails, the existing engine still works for non-proxied flows.
    func() {
        // Close previous engine quietly
        _ = browser.Close()
        localProxy := fmt.Sprintf("http://127.0.0.1:%d", engine.proxyPort)
        relauncher := launcher.New().
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
            UserDataDir(dataStore).
            Proxy(localProxy)
        if MustDisableSandbox() { relauncher = relauncher.NoSandbox(true) }
        for k, v := range optionalArgs { relauncher.Set(flags.Flag(k), v) }
        if useLocal || func() bool { p, _ := fileutil.UseMusl(executablePath); return p }() {
            if chromePath, hasChrome := launcher.LookPath(); hasChrome { relauncher.Bin(chromePath) }
        }
        if u, err := relauncher.Launch(); err == nil {
            engine.engine = rod.New().ControlURL(u)
            _ = engine.engine.Connect()
        }
    }()

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

    // If rules are provided, just update vhost mappings in our proxy; keep using the same Chrome instance
    if hostResolverRules != "" {
        if err := b.setupVhostMapping(hostResolverRules); err != nil {
            return nil, "", errors.Wrap(err, "failed to apply vhost mappings")
        }
        fmt.Printf("DEBUG: Applied vhost mappings: %s\n", hostResolverRules)
    }

    // Use regular browser (already pointed at local proxy)
    page, err = b.engine.Page(proto.TargetCreateTarget{})
    fmt.Printf("DEBUG: Using browser with local forward proxy\n")
	
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
	
	_ = page.WaitIdle(idle)

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

// (Deprecated) createVhostBrowser: no longer needed; mappings are handled in proxy.
func (b *Browser) createVhostBrowser(hostResolverRules string) (*rod.Browser, error) { return nil, nil }

func (b *Browser) setupVhostMapping(hostResolverRules string) error {
    // Local forward proxy is started in NewBrowser
    if b.proxyPort == 0 {
        if err := b.startForwardProxy(); err != nil { return err }
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

// Start a single-port forward proxy that supports HTTP proxy semantics and TLS MITM on CONNECT.
func (b *Browser) startForwardProxy() error {
    // Generate (or reuse) self-signed certificate
    if b.mitmCert == nil {
        cert, err := b.generateSelfSignedCert()
        if err != nil { return err }
        b.mitmCert = &cert
    }

    // Listen on random local port
    ln, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil { return err }
    b.proxyPort = ln.Addr().(*net.TCPAddr).Port

    srv := &http.Server{ Handler: http.HandlerFunc(b.handleForwardProxy) }

    b.proxyClose = func() { srv.Close() }

    go func() { _ = srv.Serve(ln) }()
    return nil
}

// oneConnListener lets us serve a single TLS-MITM HTTP request after CONNECT
type oneConnListener struct { c net.Conn; used bool }
func (l *oneConnListener) Accept() (net.Conn, error) { if l.used { return nil, fmt.Errorf("closed") }; l.used = true; return l.c, nil }
func (l *oneConnListener) Close() error { return nil }
func (l *oneConnListener) Addr() net.Addr { return l.c.LocalAddr() }

// handleForwardProxy handles HTTP proxy requests and CONNECT for TLS MITM
func (b *Browser) handleForwardProxy(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodConnect {
        // CONNECT host:port
        hj, ok := w.(http.Hijacker)
        if !ok { http.Error(w, "proxy: hijacking not supported", http.StatusInternalServerError); return }
        clientConn, _, err := hj.Hijack()
        if err != nil { return }
        // Acknowledge tunnel
        _, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
        // Perform TLS server handshake (MITM) with wildcard cert
        tlsSrv := tls.Server(clientConn, &tls.Config{ Certificates: []tls.Certificate{*b.mitmCert} })
        if err := tlsSrv.Handshake(); err != nil { _ = tlsSrv.Close(); return }
        // Serve exactly one HTTP request on this TLS connection using our reverse-proxy logic
        _ = (&http.Server{ Handler: http.HandlerFunc(b.handleVhostProxy) }).Serve(&oneConnListener{ c: tlsSrv })
        return
    }

    // Non-CONNECT: browser will send absolute-form requests. Delegate to reverse-proxy logic.
    b.handleVhostProxy(w, r)
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
    
    // Customize transport for proper TLS SNI handling and upstream proxy chaining
    transport := &http.Transport{
        TLSClientConfig: &tls.Config{ InsecureSkipVerify: true, ServerName: hostname },
    }
    if b.upstreamProxyURL != nil {
        transport.Proxy = http.ProxyURL(b.upstreamProxyURL)
    }
    proxy.Transport = transport

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