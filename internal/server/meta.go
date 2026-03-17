package server

// Scanner meta for /api/v1/health and RunScan (set by cmd before Listen).
var scannerVersion, scannerSource string

// SetScannerMeta is called from sslcheck api/web with main's appVersion and repo URL.
func SetScannerMeta(version, source string) {
	scannerVersion = version
	scannerSource = source
}
