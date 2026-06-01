package caa

import (
	"crypto/x509"
	"strings"

	"sslcheck/internal/model"
)
type SatisfyResult string

const (
	SatisfyNoRecords     SatisfyResult = "no_records"
	SatisfyAllowsIssuer  SatisfyResult = "allows_issuer"
	SatisfyPolicyMismatch SatisfyResult = "policy_mismatch"
	SatisfyUnknownIssuer SatisfyResult = "unknown_issuer"
)

// SatisfyResult is the CAA policy conclusion for JSON caa_satisfies_scan.
// Evaluate matches leaf issuer against CAA issue / issuewild records for hostname.
func Evaluate(host string, records []model.CAARecord, leaf *x509.Certificate) (SatisfyResult, string) {
	if leaf == nil {
		return EvaluateFromIssuerNames(host, records, "", nil)
	}
	return EvaluateFromIssuerNames(host, records, leaf.Issuer.CommonName, leaf.Issuer.Organization)
}

// EvaluateFromIssuerNames compares issuer identity against CAA without a full x509 leaf.
func EvaluateFromIssuerNames(host string, records []model.CAARecord, issuerCN string, issuerOrgs []string) (SatisfyResult, string) {
	if len(records) == 0 {
		return SatisfyNoRecords, "no CAA records returned for this name"
	}
	issuerDomain := issuerDomainFromNames(issuerCN, issuerOrgs)
	if issuerDomain == "" {
		return SatisfyUnknownIssuer, "could not derive issuer domain from leaf"
	}
	wildcard := strings.HasPrefix(host, "*.")
	tag := "issue"
	if wildcard {
		tag = "issuewild"
	}
	var allowed []string
	for _, rec := range records {
		t := strings.ToLower(strings.TrimSpace(rec.Tag))
		if t != tag && t != "issue" && !(wildcard && t == "issuewild") {
			continue
		}
		if t == "issuewild" && !wildcard {
			continue
		}
		val := normalizeCAValue(rec.Value)
		if val == ";" || val == "" {
			continue
		}
		allowed = append(allowed, val)
	}
	if len(allowed) == 0 {
		return SatisfyPolicyMismatch, "CAA present but no applicable " + tag + " authorization"
	}
	for _, ca := range allowed {
		if domainMatchesCA(issuerDomain, ca) {
			return SatisfyAllowsIssuer, "issuer " + issuerDomain + " allowed by CAA " + tag + " " + ca
		}
	}
	return SatisfyPolicyMismatch, "issuer " + issuerDomain + " not authorized by CAA (allowed: " + strings.Join(allowed, ", ") + ")"
}

func issuerDomainFromNames(issuerCN string, issuerOrgs []string) string {
	if d := domainFromName(issuerCN); d != "" {
		return d
	}
	for _, o := range issuerOrgs {
		if d := domainFromName(o); d != "" {
			return d
		}
	}
	return ""
}

func issuerDomainFromCert(leaf *x509.Certificate) string {
	return issuerDomainFromNames(leaf.Issuer.CommonName, leaf.Issuer.Organization)
}

func domainFromName(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "*.")
	if i := strings.Index(s, "."); i >= 0 {
		return s[i+1:]
	}
	return s
}

func normalizeCAValue(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	if i := strings.Index(v, ";"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	return v
}

func domainMatchesCA(issuerDomain, caValue string) bool {
	issuerDomain = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(issuerDomain)), ".")
	caValue = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(caValue)), ".")
	if issuerDomain == caValue {
		return true
	}
	return strings.HasSuffix(issuerDomain, "."+caValue)
}
