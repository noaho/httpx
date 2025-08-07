package httpx

// Target of the scan with ip|host header customization
type Target struct {
	Host       string
	CustomHost *string // nil = not set, &"" = explicitly set to empty
	CustomIP   string
	CustomSNI  *string // nil = not set, &"" = explicitly set to empty
}
