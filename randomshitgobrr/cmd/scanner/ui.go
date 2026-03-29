package main

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ── shared state ────────────────────────────────────────────────────────────

// scanStats is written by scanner goroutines (atomics + mutex) and read by the
// UI ticker — no locking needed for the atomic fields.
type scanStats struct {
	dnsDone   atomic.Int64
	dnsPassed atomic.Int64
	hsDone    atomic.Int64
	hsPassed  atomic.Int64

	mu      sync.Mutex
	pending []resultLine
	done    bool
}

func (s *scanStats) recordDNS(passed bool) {
	s.dnsDone.Add(1)
	if passed {
		s.dnsPassed.Add(1)
	}
}

func (s *scanStats) recordHS(ip string, latency time.Duration, passed bool) {
	s.hsDone.Add(1)
	if passed {
		s.hsPassed.Add(1)
		s.mu.Lock()
		s.pending = append(s.pending, resultLine{ip, latency})
		s.mu.Unlock()
	}
}

func (s *scanStats) markDone() {
	s.mu.Lock()
	s.done = true
	s.mu.Unlock()
}

type resultLine struct {
	ip      string
	latency time.Duration
}

// ── model ───────────────────────────────────────────────────────────────────

type uiConfig struct {
	total      int
	listFile   string
	domain     string
	dnsWorkers int
	hsWorkers  int
	outputFile string
	start      time.Time
}

type model struct {
	cfg     uiConfig
	stats   *scanStats
	results []resultLine
	elapsed time.Duration
	done    bool
	final   bool // second tick after done — then quit
	width   int
}

type tickMsg struct{}

func tick() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(time.Time) tea.Msg { return tickMsg{} })
}

func newModel(cfg uiConfig, stats *scanStats) model {
	return model{cfg: cfg, stats: stats, width: 80}
}

func (m model) Init() tea.Cmd { return tick() }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width

	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

	case tickMsg:
		m.elapsed = time.Since(m.cfg.start)

		m.stats.mu.Lock()
		m.results = append(m.results, m.stats.pending...)
		m.stats.pending = nil
		isDone := m.stats.done
		m.stats.mu.Unlock()

		if isDone {
			if m.done {
				m.final = true
				return m, tea.Quit
			}
			m.done = true
		}
		return m, tick()
	}
	return m, nil
}

// ── styles ──────────────────────────────────────────────────────────────────

var (
	sTitle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("99"))
	sDim      = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	sGreen    = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
	sRed      = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	sYellow   = lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
	sBar      = lipgloss.NewStyle().Foreground(lipgloss.Color("99"))
	sBarEmpty = lipgloss.NewStyle().Foreground(lipgloss.Color("237"))
	sLabel    = lipgloss.NewStyle().Bold(true).Width(12)

	sLatFast = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
	sLatMed  = lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
	sLatSlow = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
)

// ── helpers ──────────────────────────────────────────────────────────────────

const barWidth = 34

func drawBar(done, total int) string {
	if total <= 0 {
		return sBarEmpty.Render(strings.Repeat("░", barWidth))
	}
	n := barWidth * done / total
	if n > barWidth {
		n = barWidth
	}
	return sBar.Render(strings.Repeat("█", n)) + sBarEmpty.Render(strings.Repeat("░", barWidth-n))
}

func latStyle(d time.Duration) lipgloss.Style {
	switch {
	case d < 200*time.Millisecond:
		return sLatFast
	case d < 600*time.Millisecond:
		return sLatMed
	default:
		return sLatSlow
	}
}

func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%02d:%02d", m, s)
}

// ── view ─────────────────────────────────────────────────────────────────────

const maxShownResults = 8

func (m model) View() string {
	dnsDone := int(m.stats.dnsDone.Load())
	dnsPassed := int(m.stats.dnsPassed.Load())
	hsDone := int(m.stats.hsDone.Load())
	hsPassed := int(m.stats.hsPassed.Load())

	w := m.width
	if w < 64 {
		w = 64
	}
	rule := sDim.Render(strings.Repeat("─", w-4))

	var sb strings.Builder
	sb.WriteString("\n")

	// ── header ──
	sb.WriteString("  " + sTitle.Render("hybrid-scanner") + "\n")
	sb.WriteString("  " + sDim.Render(fmt.Sprintf(
		"%d IPs · %s · dns-workers=%d hs-workers=%d",
		m.cfg.total, m.cfg.domain, m.cfg.dnsWorkers, m.cfg.hsWorkers,
	)) + "\n\n")

	// ── DNS stage ──
	sb.WriteString("  " + sLabel.Render("DNS Check") + sDim.Render("stage 2") + "\n")
	sb.WriteString("  " + drawBar(dnsDone, m.cfg.total) +
		"  " + sDim.Render(fmt.Sprintf("%d / %d", dnsDone, m.cfg.total)) + "\n")
	sb.WriteString(fmt.Sprintf("  %s   %s\n\n",
		sGreen.Render(fmt.Sprintf("✓ %d passed", dnsPassed)),
		sRed.Render(fmt.Sprintf("✗ %d failed", dnsDone-dnsPassed)),
	))

	// ── Handshake stage ──
	hsTotal := dnsPassed
	if hsTotal == 0 {
		hsTotal = 1
	}
	sb.WriteString("  " + sLabel.Render("Handshake") + sDim.Render("stage 3") + "\n")
	sb.WriteString("  " + drawBar(hsDone, hsTotal) +
		"  " + sDim.Render(fmt.Sprintf("%d / %d", hsDone, dnsPassed)) + "\n")
	sb.WriteString(fmt.Sprintf("  %s   %s\n\n",
		sGreen.Render(fmt.Sprintf("✓ %d passed", hsPassed)),
		sRed.Render(fmt.Sprintf("✗ %d failed", hsDone-hsPassed)),
	))

	// ── results feed ──
	results := m.results
	if len(results) > maxShownResults {
		results = results[len(results)-maxShownResults:]
	}
	if len(results) > 0 {
		sb.WriteString("  " + rule + "\n")
		for _, r := range results {
			ms := r.latency.Milliseconds()
			sb.WriteString(fmt.Sprintf("  %s  %-18s  %s\n",
				sGreen.Render("✓"),
				r.ip,
				latStyle(r.latency).Render(fmt.Sprintf("%d ms", ms)),
			))
		}
		sb.WriteString("\n")
	}

	// ── footer ──
	sb.WriteString("  " + rule + "\n")
	var elapsedStr string
	if m.done {
		elapsedStr = sGreen.Render("✓ done  " + fmtDuration(m.elapsed))
	} else {
		elapsedStr = sYellow.Render("⏱  " + fmtDuration(m.elapsed))
	}
	sb.WriteString(fmt.Sprintf("  %s   %s\n\n",
		elapsedStr,
		sDim.Render("→ "+m.cfg.outputFile),
	))

	return sb.String()
}
