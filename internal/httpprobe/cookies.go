package httpprobe

import (
	"net/http"

	"sslcheck/internal/model"
)

func assessCookies(cookies []*http.Cookie) []model.CookieIssue {
	var issues []model.CookieIssue
	for _, c := range cookies {
		var problems []string
		if !c.Secure { problems = append(problems, "missing Secure") }
		if !c.HttpOnly { problems = append(problems, "missing HttpOnly") }
		if c.SameSite == http.SameSiteDefaultMode { problems = append(problems, "missing explicit SameSite") }
		if c.Path == "" { problems = append(problems, "missing explicit Path") }
		if len(problems) > 0 {
			issues = append(issues, model.CookieIssue{Name: c.Name, Problems: problems})
		}
	}
	return issues
}
