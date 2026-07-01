package build

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// status prints a live status line to stderr, updating in-place every 150ms.
//
// Primary counter (done) drives the progress bar when total > 0.
// Optional extra counter (addExtra) is shown alongside and used for rate/s.
// Stop() prints a final newline and cleans up.
type status struct {
	label      string
	total      int64        // -1 = unknown; drives progress bar
	done       atomic.Int64 // primary counter
	rateLabel  string       // label for rate, e.g. "entries" → "12,345 entries/s"
	extra      atomic.Int64 // secondary counter (shown + used for rate when rateLabel != "")
	start      time.Time
	ticker     *time.Ticker
	stopCh     chan struct{}
	stoppedCh  chan struct{}
}

func newStatus(label string, total int64, rateLabel string) *status {
	s := &status{
		label:     label,
		total:     total,
		rateLabel: rateLabel,
		start:     time.Now(),
		ticker:    time.NewTicker(150 * time.Millisecond),
		stopCh:    make(chan struct{}),
		stoppedCh: make(chan struct{}),
	}
	go s.run()
	return s
}

func (s *status) add(n int64)      { s.done.Add(n) }
func (s *status) addExtra(n int64) { s.extra.Add(n) }

func (s *status) stop() {
	close(s.stopCh)
	<-s.stoppedCh
}

func (s *status) run() {
	defer close(s.stoppedCh)
	defer s.ticker.Stop()
	for {
		select {
		case <-s.ticker.C:
			s.print()
		case <-s.stopCh:
			s.print()
			fmt.Fprint(os.Stderr, "\n")
			return
		}
	}
}

func (s *status) print() {
	cur := s.done.Load()
	elapsed := time.Since(s.start).Seconds()
	if elapsed < 0.001 {
		elapsed = 0.001
	}

	var sb strings.Builder
	sb.WriteString(s.label)

	if s.total > 0 {
		pct := float64(cur) / float64(s.total)
		fmt.Fprintf(&sb, "  [%s]  %s / %s",
			progressBar(pct, 20), commaSep(cur), commaSep(s.total))
	} else {
		fmt.Fprintf(&sb, "  %s", commaSep(cur))
	}

	// Secondary counter (e.g. entries when primary is tiles).
	var rateBase float64
	if s.rateLabel != "" {
		ext := s.extra.Load()
		fmt.Fprintf(&sb, "  %s %s", commaSep(ext), s.rateLabel)
		rateBase = float64(ext) / elapsed
	} else {
		rateBase = float64(cur) / elapsed
	}

	// Rate.
	fmt.Fprintf(&sb, "  %.0f/s", rateBase)

	// ETA: computed from the primary counter rate (tiles or entries).
	if s.total > 0 && cur < s.total {
		primaryRate := float64(cur) / elapsed
		if primaryRate > 0 {
			remaining := time.Duration(float64(s.total-cur)/primaryRate) * time.Second
			fmt.Fprintf(&sb, "  ETA %s", remaining.Round(time.Second))
		}
	}

	fmt.Fprintf(os.Stderr, "\r\033[K%s", sb.String())
}

func progressBar(frac float64, width int) string {
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	filled := int(frac * float64(width))
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}
