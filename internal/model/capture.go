package model

// Capture is probe output from an agent-side collect run (no cert analysis or findings).
type Capture struct {
	URL          string        `json:"url"`
	Host         string        `json:"host"`
	Port         string        `json:"port"`
	StartedAt    string        `json:"started_at,omitempty"`
	PhaseTimings []PhaseTiming `json:"phase_timings,omitempty"`
	DNS          DNSResult     `json:"dns"`
	DNSLookupErr string        `json:"dns_lookup_err,omitempty"`
	SkipHTTP     bool          `json:"skip_http,omitempty"`
	FastScan     bool          `json:"fast_scan,omitempty"`
	Redirect     HTTPRedirectResult `json:"redirect,omitempty"`
	RedirectChain []string     `json:"redirect_chain,omitempty"`
	RedirectChainErr string    `json:"redirect_chain_err,omitempty"`
	HTTP         HTTPResult    `json:"http,omitempty"`
	Endpoints    []EndpointCapture `json:"endpoints,omitempty"`
}

// EndpointCapture holds per-IP TLS probe material for server-side analysis.
type EndpointCapture struct {
	IP                string `json:"ip"`
	Network           string `json:"network"`
	TCPReachable      bool   `json:"tcp_reachable"`
	TCPConnectLatency string `json:"tcp_connect_latency,omitempty"`
	TCPDialErr        string `json:"tcp_dial_err,omitempty"`

	TLSHandshakeOK bool   `json:"tls_handshake_ok"`
	HandshakeErr   string `json:"handshake_err,omitempty"`
	TLSVersion     string `json:"tls_version,omitempty"`
	CipherSuite    string `json:"cipher_suite,omitempty"`
	TLSVersionID   uint16 `json:"tls_version_id,omitempty"`
	CipherSuiteID  uint16 `json:"cipher_suite_id,omitempty"`
	ServerName     string `json:"server_name,omitempty"`
	ALPN           string `json:"alpn,omitempty"`
	PeerCertCount  int    `json:"peer_cert_count,omitempty"`

	OCSPStapledResponse []byte `json:"ocsp_stapled_response,omitempty"`
	SCTCount            int    `json:"sct_count,omitempty"`

	PeerCertsDER   [][]byte `json:"peer_certs_der,omitempty"`
	FullChainDER   [][]byte `json:"full_chain_der,omitempty"`
	ChainBuildNotes []string `json:"chain_build_notes,omitempty"`
	ChainFetchedFP map[string]bool `json:"chain_fetched_fp,omitempty"`
	ChainVerifiedOK bool `json:"chain_verified_ok,omitempty"`

	ActiveOCSP []ActiveOCSPCapture `json:"active_ocsp,omitempty"`
	CRLBody    []byte              `json:"crl_body,omitempty"`
	CRLFetchErr string             `json:"crl_fetch_err,omitempty"`
	CRLChecked bool                `json:"crl_checked,omitempty"`
	CRLStatus  string              `json:"crl_status,omitempty"`

	ProtocolSupport   map[string]bool `json:"protocol_support,omitempty"`
	WeakCipherSupport []string        `json:"weak_cipher_support,omitempty"`
	ALPNProbe         *ALPNResult     `json:"alpn_probe,omitempty"`
	Resumption        *ResumptionResult `json:"resumption,omitempty"`
	CipherPreference  *CipherPreferenceResult `json:"cipher_preference,omitempty"`
	SupportedGroups   []string        `json:"supported_groups,omitempty"`

	WrongSNIOutcome string `json:"wrong_sni_outcome,omitempty"` // rejected | same_cert | fallback_cert
	WrongSNIFallbackCN string `json:"wrong_sni_fallback_cn,omitempty"`
	FallbackSCSVAccepted bool `json:"fallback_scsv_accepted,omitempty"`

	TLSErrorNoSNI    string   `json:"tls_error_no_sni,omitempty"`
	NoSNIHandshakeOK bool     `json:"no_sni_handshake_ok"`
	NoSNICertCN      string   `json:"no_sni_chosen_cert_cn,omitempty"`
	NoSNICertSANs    []string `json:"no_sni_chosen_sans,omitempty"`

	ClientAuthRequested bool     `json:"client_auth_requested,omitempty"`
	Errors              []string `json:"errors,omitempty"`
	Warnings            []string `json:"warnings,omitempty"`
	Fast                bool     `json:"fast,omitempty"`
}

// ActiveOCSPCapture is a raw OCSP HTTP response from collect.
type ActiveOCSPCapture struct {
	URL         string `json:"url"`
	Body        []byte `json:"body,omitempty"`
	FetchErr    string `json:"fetch_err,omitempty"`
	ParseErr    string `json:"parse_err,omitempty"`
	Status      string `json:"status,omitempty"` // good | revoked | unknown
}
