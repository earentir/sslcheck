package report

import (
	"encoding/csv"
	"io"
	"strconv"

	"sslcheck/internal/model"
)

// CSV writes findings from the reports as CSV to w. One row per finding; multiple
// reports are combined with url column identifying the source.
func CSV(w io.Writer, reports []*model.Report) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()
	header := []string{"url", "host", "overall", "finding_count", "code", "severity", "title", "description", "evidence", "remediation"}
	if err := writer.Write(header); err != nil {
		return err
	}
	for _, rep := range reports {
		n := strconv.Itoa(len(rep.Findings))
		for _, f := range rep.Findings {
			row := []string{
				rep.URL,
				rep.Host,
				rep.Overall,
				n,
				f.Code,
				string(f.Severity),
				f.Title,
				f.Description,
				f.Evidence,
				f.Remediation,
			}
			if err := writer.Write(row); err != nil {
				return err
			}
		}
		// If no findings, emit one row with url/host/overall/count so the URL appears
		if len(rep.Findings) == 0 {
			row := []string{rep.URL, rep.Host, rep.Overall, "0", "", "", "", "", "", ""}
			if err := writer.Write(row); err != nil {
				return err
			}
		}
	}
	return nil
}
