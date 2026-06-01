package report

import (
	"fmt"
	"strings"

	"sslcheck/internal/model"
)

// RenderPhaseTimingsTable formats phase_timings as a plain-text table for terminal output.
func RenderPhaseTimingsTable(timings []model.PhaseTiming, totalMS int64) string {
	if len(timings) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Scan timing\n")
	fmt.Fprintf(&b, "  %-36s %8s %7s\n", "Phase", "ms", "%")
	fmt.Fprintf(&b, "  %s\n", strings.Repeat("-", 54))
	var sum int64
	for _, t := range timings {
		pct := pctOf(t.DurationMS, totalMS)
		fmt.Fprintf(&b, "  %-36s %8d %6.1f%%\n", t.Name, t.DurationMS, pct)
		sum += t.DurationMS
	}
	fmt.Fprintf(&b, "  %s\n", strings.Repeat("-", 54))
	if overhead := totalMS - sum; overhead > 5 {
		fmt.Fprintf(&b, "  %-36s %8d %6.1f%%\n", "Overhead (between phases)", overhead, pctOf(overhead, totalMS))
	}
	fmt.Fprintf(&b, "  %-36s %8d\n", "Total (wall clock)", totalMS)
	return b.String()
}

func pctOf(part, total int64) float64 {
	if total <= 0 {
		return 0
	}
	return float64(part) / float64(total) * 100
}
