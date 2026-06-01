package model

import (
	"fmt"
	"sort"
	"strings"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Finding struct {
	Code          string   `json:"code"`
	Severity      Severity `json:"severity"`
	Title         string   `json:"title"`
	Description   string   `json:"description"`
	Evidence      string   `json:"evidence,omitempty"`
	Remediation   string   `json:"remediation,omitempty"`
	ReferenceURL  string   `json:"reference_url,omitempty"` // optional documentation (e.g. MDN)
}

type CAARecord struct {
	Flag  uint8  `json:"flag"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

type TLSARecord struct {
	Usage        uint8  `json:"usage"`
	Selector     uint8  `json:"selector"`
	MatchingType uint8  `json:"matching_type"`
	Certificate  string `json:"certificate"` // hex
}

type DNSResult struct {
	Host              string       `json:"host"`
	Port              string       `json:"port"`
	IPs               []string     `json:"ips"`
	CNAME             string       `json:"cname,omitempty"`
	CAARecords        []CAARecord  `json:"caa_records"`
	CAASatisfiesScan  string       `json:"caa_satisfies_scan,omitempty"` // no_records | allows_issuer | policy_mismatch | unknown_issuer
	TLSARecords       []TLSARecord `json:"tlsa_records"`
	LookupMS          int64        `json:"lookup_ms"`
}

type HTTPRedirectResult struct {
	HTTPURL          string `json:"http_url"`
	StatusCode       int    `json:"status_code,omitempty"`
	Location         string `json:"location,omitempty"`
	RedirectsToHTTPS bool   `json:"redirects_to_https"`
	Error            string `json:"error,omitempty"`
}

type CookieIssue struct {
	Name     string   `json:"name"`
	Problems []string `json:"problems"`
}

type HeaderIssue struct {
	Header   string `json:"header"`
	Problem  string `json:"problem"`
	Observed string `json:"observed,omitempty"`
}

type SubresourceRef struct {
	URL      string `json:"url"`
	Kind     string `json:"kind"`
	Hostname string `json:"hostname,omitempty"`
}

type SubresourceHostResult struct {
	Host             string   `json:"host"`
	IPs              []string `json:"ips,omitempty"`
	TLSOK            bool     `json:"tls_ok"`
	TrustOK          bool     `json:"trust_ok"`
	HostnameMatchOK  bool     `json:"hostname_match_ok"`
	Error            string   `json:"error,omitempty"`
}

type HTTPResult struct {
	FinalURL              string                `json:"final_url,omitempty"`
	StatusCode            int                   `json:"status_code,omitempty"`
	HSTS                  string                `json:"hsts,omitempty"`
	HSTSMaxAge            int                   `json:"hsts_max_age,omitempty"`
	HSTSIncludeSubDomains bool                  `json:"hsts_include_subdomains"`
	HSTSPreload           bool                  `json:"hsts_preload"`
	AltSvc                string                `json:"alt_svc,omitempty"`
	Server                string                `json:"server,omitempty"`
	Protocol              string                `json:"protocol,omitempty"`
	CookieIssues          []CookieIssue         `json:"cookie_issues,omitempty"`
	HeaderIssues          []HeaderIssue         `json:"header_issues,omitempty"`
	MixedContentHits      []string              `json:"mixed_content_hits,omitempty"`
	SubresourceRefs       []SubresourceRef      `json:"subresource_refs,omitempty"`
	SubresourceHosts      []SubresourceHostResult `json:"subresource_hosts,omitempty"`
	Error                 string                `json:"error,omitempty"`
}

// ChainCertificateDetail describes one certificate in the validated chain (leaf → root).
type ChainCertificateDetail struct {
	Role               string   `json:"role"` // leaf, intermediate, root
	Subject            string   `json:"subject"`
	Issuer             string   `json:"issuer"`
	Serial             string   `json:"serial"`
	NotBefore          string   `json:"not_before"`
	NotAfter           string   `json:"not_after"`
	DaysUntilExpiry    int      `json:"days_until_expiry"`
	Source             string   `json:"source"` // from_server, fetched_aia, trust_anchor
	SignatureAlgorithm string   `json:"signature_algorithm,omitempty"`
	PublicKeyStrength  string   `json:"public_key_strength,omitempty"`
	KeyUsage           []string `json:"key_usage,omitempty"`
	IsCA               bool     `json:"is_ca"`
}

type CertificateSummary struct {
	SubjectCommonName   string   `json:"subject_common_name,omitempty"`
	DNSNames            []string `json:"dns_names,omitempty"`
	IssuerCommonName    string   `json:"issuer_common_name,omitempty"`
	SerialNumber        string   `json:"serial_number,omitempty"`
	NotBefore           string   `json:"not_before,omitempty"`
	NotAfter            string   `json:"not_after,omitempty"`
	DaysUntilExpiry     int      `json:"days_until_expiry"`
	SignatureAlgorithm  string   `json:"signature_algorithm,omitempty"`
	PublicKeyAlgorithm  string   `json:"public_key_algorithm,omitempty"`
	PublicKeyStrength   string   `json:"public_key_strength,omitempty"`
	KeyUsage            []string `json:"key_usage,omitempty"`
	ExtKeyUsage         []string `json:"ext_key_usage,omitempty"`
	IsCA                bool     `json:"is_ca"`
	SPKISHA256         string   `json:"spki_sha256,omitempty"`
	CertSHA256         string   `json:"cert_sha256,omitempty"`
	HostnameVerified    bool     `json:"hostname_verified"`
	TrustVerified       bool     `json:"trust_verified"`
	TrustError          string   `json:"trust_error,omitempty"`
	HostnameVerifyError string   `json:"hostname_verify_error,omitempty"`
	ChainSubjects       []string `json:"chain_subjects,omitempty"`
	OCSPServers         []string `json:"ocsp_servers,omitempty"`
	CRLDistribution     []string `json:"crl_distribution_points,omitempty"`
}

type ResumptionResult struct {
	TLS12Attempted bool `json:"tls12_attempted"`
	TLS12Resumed   bool `json:"tls12_resumed"`
	TLS13Attempted bool `json:"tls13_attempted"`
	TLS13Resumed   bool `json:"tls13_resumed"`
}

type ALPNResult struct {
	H2WhenOnly     bool   `json:"h2_when_only"`
	HTTP11WhenOnly bool   `json:"http11_when_only"`
	H2OnlyError    string `json:"h2_only_error,omitempty"`
	HTTP11OnlyError string `json:"http11_only_error,omitempty"`
}

type CipherPreferenceResult struct {
	Attempted     bool   `json:"attempted"`
	ServerPrefers bool   `json:"server_prefers"`
	Observed      string `json:"observed,omitempty"`
}

// CertificateTransparencySummary is CT/SCT facts for JSON consumers.
type CertificateTransparencySummary struct {
	SCTCount     int      `json:"sct_count"`
	SCTSources   []string `json:"sct_sources,omitempty"` // embedded, tls_handshake
	CTCompliance string   `json:"ct_compliance"`         // unknown | likely_ok | failed
}

// RevocationSummary aggregates stapled/active OCSP and CRL checks for the leaf.
type RevocationSummary struct {
	StapledOCSP          bool   `json:"stapled_ocsp"`
	StapledOCSPStatus    string `json:"stapled_ocsp_status,omitempty"` // good | revoked | unknown | parse_error | none
	ActiveOCSPStatus     string `json:"active_ocsp_status,omitempty"`  // good | revoked | unknown | unreachable | not_checked
	CRLChecked           bool   `json:"crl_checked"`
	CRLStatus            string `json:"crl_status,omitempty"` // good | revoked | unreachable | not_checked | no_urls
	MustStapleRequired   bool   `json:"must_staple_required"`
	OverallRevocationStatus string `json:"revocation_status"` // good | revoked | unknown | incomplete
}

type EndpointResult struct {
	IP                string               `json:"ip"`
	Network           string               `json:"network"`
	TCPReachable      bool                 `json:"tcp_reachable"`
	TCPConnectLatency string               `json:"tcp_connect_latency,omitempty"`
	TLSHandshakeOK    bool                 `json:"tls_handshake_ok"`
	TLSVersion        string               `json:"tls_version,omitempty"`
	CipherSuite       string               `json:"cipher_suite,omitempty"`
	ServerName        string               `json:"server_name,omitempty"`
	ALPN              string               `json:"alpn,omitempty"`
	ALPNProbe         *ALPNResult          `json:"alpn_probe,omitempty"`
	Resumption        *ResumptionResult    `json:"resumption,omitempty"`
	CipherPreference  *CipherPreferenceResult `json:"cipher_preference,omitempty"`
	PeerCertCount     int                  `json:"peer_cert_count,omitempty"`
	ProtocolSupport   map[string]bool      `json:"protocol_support,omitempty"`
	WeakCipherSupport []string             `json:"weak_cipher_support"`
	OCSPStapled       bool                 `json:"ocsp_stapled"`
	OCSPStatus        string               `json:"ocsp_status,omitempty"` // deprecated: use ocsp_stapled_status when stapled
	OCSPStapledStatus string               `json:"ocsp_stapled_status,omitempty"`
	CertificateTransparency *CertificateTransparencySummary `json:"certificate_transparency,omitempty"`
	Revocation            *RevocationSummary              `json:"revocation,omitempty"`
	ClientAuthRequested   bool                            `json:"client_auth_requested,omitempty"`
	SCTCount          int                  `json:"sct_count,omitempty"`
	CertSummary       *CertificateSummary  `json:"cert_summary,omitempty"`
	Errors            []string             `json:"errors,omitempty"`
	Warnings          []string             `json:"warnings,omitempty"`
	Findings          []Finding            `json:"findings,omitempty"`
	TLSErrorNoSNI     string               `json:"tls_error_no_sni,omitempty"`
	NoSNIHandshakeOK  bool                 `json:"no_sni_handshake_ok"`
	NoSNICertCN       string               `json:"no_sni_chosen_cert_cn,omitempty"`
	NoSNICertSANs     []string             `json:"no_sni_chosen_sans,omitempty"`
	CertificateChainDetails []ChainCertificateDetail `json:"certificate_chain,omitempty"`
	ChainBuildNotes         []string                 `json:"chain_build_notes,omitempty"`
}

type PhaseTiming struct {
	Name       string `json:"name"`
	DurationMS int64  `json:"duration_ms"`
}

type Report struct {
	URL           string             `json:"url"`
	Host          string             `json:"host"`
	Port          string             `json:"port"`
	DNS           DNSResult          `json:"dns"`
	Redirect      HTTPRedirectResult `json:"redirect"`
	RedirectChain []string           `json:"redirect_chain,omitempty"`
	HTTP          HTTPResult         `json:"http"`
	Endpoints     []EndpointResult   `json:"endpoints"`
	Findings      []Finding          `json:"findings"`
	StartedAt     string             `json:"started_at"`
	FinishedAt    string             `json:"finished_at"`
	DurationMS    int64              `json:"duration_ms"`
	Overall       string             `json:"overall"`
	// Primary certificate chain (first successful TLS endpoint); full leaf→root with AIA-fetched certs.
	CertificateChain   []ChainCertificateDetail `json:"certificate_chain,omitempty"`
	ChainBuildNotes      []string               `json:"chain_build_notes,omitempty"`
	LeafDaysUntilExpiry  int                    `json:"leaf_days_until_expiry"`
	LeafNotAfter         string                 `json:"leaf_not_after,omitempty"`
	// ScannerVersion is the sslcheck binary version (API/JSON).
	ScannerVersion string `json:"scanner_version,omitempty"`
	// ScannerSource is the project URL (API/JSON).
	ScannerSource string `json:"scanner_source,omitempty"`
	// PhaseTimings is per-step wall time (always last in JSON output).
	PhaseTimings []PhaseTiming `json:"phase_timings"`
}

func SeverityRank(s Severity) int {
	switch s {
	case SeverityInfo:
		return 1
	case SeverityLow:
		return 2
	case SeverityMedium:
		return 3
	case SeverityHigh:
		return 4
	case SeverityCritical:
		return 5
	default:
		return 0
	}
}

func SortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		ri := SeverityRank(findings[i].Severity)
		rj := SeverityRank(findings[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return findings[i].Code < findings[j].Code
	})
}

func (r Report) RenderText() string {
	var b strings.Builder

	fmt.Fprintf(&b, "Overall: %s\n", strings.ToUpper(r.Overall))
	fmt.Fprintf(&b, "URL: %s\nHost: %s\nPort: %s\n\n", r.URL, r.Host, r.Port)

	fmt.Fprintf(&b, "DNS\n  Lookup: %d ms\n", r.DNS.LookupMS)
	if r.DNS.CNAME != "" {
		fmt.Fprintf(&b, "  CNAME: %s\n", r.DNS.CNAME)
	}
	fmt.Fprintf(&b, "  IPs: %s\n", strings.Join(r.DNS.IPs, ", "))
	if len(r.DNS.CAARecords) > 0 {
		fmt.Fprintf(&b, "  CAA:\n")
		for _, rec := range r.DNS.CAARecords {
			fmt.Fprintf(&b, "    - flag=%d tag=%s value=%s\n", rec.Flag, rec.Tag, rec.Value)
		}
	}
	fmt.Fprintf(&b, "\n")

	fmt.Fprintf(&b, "HTTP redirect\n  URL: %s\n", r.Redirect.HTTPURL)
	if r.Redirect.Error != "" {
		fmt.Fprintf(&b, "  Error: %s\n\n", r.Redirect.Error)
	} else {
		fmt.Fprintf(&b, "  Status: %d\n  Location: %s\n  Redirects to HTTPS: %v\n\n",
			r.Redirect.StatusCode, r.Redirect.Location, r.Redirect.RedirectsToHTTPS)
	}

	fmt.Fprintf(&b, "HTTPS application probe\n")
	if r.HTTP.Error != "" {
		fmt.Fprintf(&b, "  Error: %s\n\n", r.HTTP.Error)
	} else {
		fmt.Fprintf(&b, "  Final URL: %s\n  Status: %d\n  Proto: %s\n  HSTS: %s\n",
			r.HTTP.FinalURL, r.HTTP.StatusCode, r.HTTP.Protocol, r.HTTP.HSTS)
		if r.HTTP.AltSvc != "" {
			fmt.Fprintf(&b, "  Alt-Svc: %s\n", r.HTTP.AltSvc)
		}
		if len(r.HTTP.HeaderIssues) > 0 {
			fmt.Fprintf(&b, "  Header issues:\n")
			for _, hi := range r.HTTP.HeaderIssues {
				fmt.Fprintf(&b, "    - %s: %s", hi.Header, hi.Problem)
				if hi.Observed != "" {
					fmt.Fprintf(&b, " (%s)", hi.Observed)
				}
				fmt.Fprintln(&b)
			}
		}
		if len(r.HTTP.CookieIssues) > 0 {
			fmt.Fprintf(&b, "  Cookie issues:\n")
			for _, ci := range r.HTTP.CookieIssues {
				fmt.Fprintf(&b, "    - %s: %s\n", ci.Name, strings.Join(ci.Problems, ", "))
			}
		}
		if len(r.HTTP.MixedContentHits) > 0 {
			fmt.Fprintf(&b, "  Mixed content hits:\n")
			for _, hit := range r.HTTP.MixedContentHits {
				fmt.Fprintf(&b, "    - %s\n", hit)
			}
		}
		if len(r.HTTP.SubresourceHosts) > 0 {
			fmt.Fprintf(&b, "  Subresource hosts:\n")
			for _, sr := range r.HTTP.SubresourceHosts {
				fmt.Fprintf(&b, "    - %s tls=%v trust=%v hostname=%v", sr.Host, sr.TLSOK, sr.TrustOK, sr.HostnameMatchOK)
				if sr.Error != "" {
					fmt.Fprintf(&b, " error=%s", sr.Error)
				}
				fmt.Fprintln(&b)
			}
		}
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "Endpoints\n")
	for _, ep := range r.Endpoints {
		fmt.Fprintf(&b, "  %s (%s)\n", ep.IP, ep.Network)
		fmt.Fprintf(&b, "    TCP reachable: %v\n", ep.TCPReachable)
		if ep.TCPConnectLatency != "" {
			fmt.Fprintf(&b, "    TCP latency: %s\n", ep.TCPConnectLatency)
		}
		fmt.Fprintf(&b, "    TLS handshake: %v\n", ep.TLSHandshakeOK)
		if ep.TLSHandshakeOK {
			fmt.Fprintf(&b, "    TLS version: %s\n    Cipher: %s\n    ALPN: %s\n", ep.TLSVersion, ep.CipherSuite, ep.ALPN)
			if ep.ALPNProbe != nil {
				fmt.Fprintf(&b, "    ALPN h2 accepted: %v\n    ALPN http/1.1 accepted: %v\n", ep.ALPNProbe.H2WhenOnly, ep.ALPNProbe.HTTP11WhenOnly)
			}
			if ep.Resumption != nil {
				fmt.Fprintf(&b, "    TLS1.2 resumed: %v\n    TLS1.3 resumed: %v\n", ep.Resumption.TLS12Resumed, ep.Resumption.TLS13Resumed)
			}
			if ep.CipherPreference != nil && ep.CipherPreference.Attempted {
				fmt.Fprintf(&b, "    Server cipher preference: %v\n", ep.CipherPreference.ServerPrefers)
			}
			fmt.Fprintf(&b, "    OCSP stapled: %v\n", ep.OCSPStapled)
			if ep.OCSPStatus != "" {
				fmt.Fprintf(&b, "    OCSP status: %s\n", ep.OCSPStatus)
			}
			fmt.Fprintf(&b, "    SCTs: %d\n", ep.SCTCount)
			if ep.CertSummary != nil {
				fmt.Fprintf(&b, "    Leaf CN: %s\n    SANs: %s\n    Issuer: %s\n",
					ep.CertSummary.SubjectCommonName,
					strings.Join(ep.CertSummary.DNSNames, ", "),
					ep.CertSummary.IssuerCommonName)
				fmt.Fprintf(&b, "    Expiry: %s (%d days)\n    Hostname verified: %v\n    Trust verified: %v\n",
					ep.CertSummary.NotAfter,
					ep.CertSummary.DaysUntilExpiry,
					ep.CertSummary.HostnameVerified,
					ep.CertSummary.TrustVerified)
				fmt.Fprintf(&b, "    Key: %s\n    Signature: %s\n",
					ep.CertSummary.PublicKeyStrength,
					ep.CertSummary.SignatureAlgorithm)
			}
		}
		if len(ep.ProtocolSupport) > 0 {
			fmt.Fprintf(&b, "    Protocol support: TLS1.0=%v TLS1.1=%v TLS1.2=%v TLS1.3=%v\n",
				ep.ProtocolSupport["TLS1.0"], ep.ProtocolSupport["TLS1.1"], ep.ProtocolSupport["TLS1.2"], ep.ProtocolSupport["TLS1.3"])
		}
		if len(ep.WeakCipherSupport) > 0 {
			fmt.Fprintf(&b, "    Weak ciphers accepted: %s\n", strings.Join(ep.WeakCipherSupport, ", "))
		}
		if ep.NoSNIHandshakeOK {
			fmt.Fprintf(&b, "    No-SNI handshake: true\n")
		} else if ep.TLSErrorNoSNI != "" {
			fmt.Fprintf(&b, "    No-SNI handshake error: %s\n", ep.TLSErrorNoSNI)
		}
	}

	fmt.Fprintf(&b, "\nFindings\n")
	if len(r.Findings) == 0 {
		fmt.Fprintf(&b, "  none\n")
		return b.String()
	}
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "  [%s] %s %s\n    %s\n", strings.ToUpper(string(f.Severity)), f.Code, f.Title, f.Description)
		if f.Evidence != "" {
			fmt.Fprintf(&b, "    Evidence: %s\n", f.Evidence)
		}
		if f.Remediation != "" {
			fmt.Fprintf(&b, "    Remediation: %s\n", f.Remediation)
		}
	}
	return b.String()
}
