package httpprobe

import (
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"

	"sslcheck/internal/model"
	"sslcheck/internal/util"
)

var cssURLRe = regexp.MustCompile(`(?i)url\((?:[[:space:]]*['"]?)?([^'")[:space:]]+)(?:['"]?[[:space:]]*)\)`)

func discoverSubresources(body []byte, baseURL *url.URL) []model.SubresourceRef {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil
	}

	var out []model.SubresourceRef
	var walk func(*html.Node)

	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			for _, attr := range n.Attr {
				kind, ok := attrKind(n.Data, attr.Key)
				if ok {
					ref := normalizeRef(baseURL, attr.Val, kind)
					if ref.URL != "" {
						out = append(out, ref)
					}
				}

				if attr.Key == "style" {
					for _, m := range cssURLRe.FindAllStringSubmatch(attr.Val, -1) {
						if len(m) < 2 {
							continue
						}
						ref := normalizeRef(baseURL, m[1], "style")
						if ref.URL != "" {
							out = append(out, ref)
						}
					}
				}
			}
		}

		if n.Type == html.TextNode && n.Parent != nil && n.Parent.Type == html.ElementNode && n.Parent.Data == "style" {
			for _, m := range cssURLRe.FindAllStringSubmatch(n.Data, -1) {
				if len(m) < 2 {
					continue
				}
				ref := normalizeRef(baseURL, m[1], "style")
				if ref.URL != "" {
					out = append(out, ref)
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}

	walk(doc)

	seen := make(map[string]model.SubresourceRef)
	for _, r := range out {
		seen[r.Kind+"|"+r.URL] = r
	}

	var dedup []model.SubresourceRef
	for _, v := range seen {
		dedup = append(dedup, v)
	}

	return dedup
}

func attrKind(tag, attr string) (string, bool) {
	switch attr {
	case "src":
		return tag, true
	case "href":
		if tag == "link" || tag == "a" {
			return tag, true
		}
	case "action":
		if tag == "form" {
			return tag, true
		}
	}
	return "", false
}

func normalizeRef(baseURL *url.URL, raw, kind string) model.SubresourceRef {
	raw = strings.TrimSpace(raw)
	if raw == "" ||
		strings.HasPrefix(raw, "data:") ||
		strings.HasPrefix(raw, "javascript:") ||
		strings.HasPrefix(raw, "mailto:") {
		return model.SubresourceRef{}
	}

	u, err := baseURL.Parse(raw)
	if err != nil {
		return model.SubresourceRef{}
	}

	return model.SubresourceRef{
		URL:      u.String(),
		Kind:     kind,
		Hostname: u.Hostname(),
	}
}

func mixedContentFromRefs(refs []model.SubresourceRef) []string {
	var hits []string
	for _, r := range refs {
		lu := strings.ToLower(r.URL)
		if strings.HasPrefix(lu, "http://") || strings.HasPrefix(lu, "ws://") {
			hits = append(hits, r.Kind+": "+r.URL)
		}
	}
	return util.UniqueSortedStrings(hits)
}

func activeHTTPSHosts(refs []model.SubresourceRef, pageHost string) []string {
	var hosts []string
	for _, r := range refs {
		lu := strings.ToLower(r.URL)
		if !strings.HasPrefix(lu, "https://") {
			continue
		}

		switch r.Kind {
		case "script", "iframe", "link", "form":
			if r.Hostname != "" && !strings.EqualFold(r.Hostname, pageHost) {
				hosts = append(hosts, r.Hostname)
			}
		}
	}

	return util.UniqueSortedStrings(hosts)
}
