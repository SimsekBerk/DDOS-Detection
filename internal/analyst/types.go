// Package analyst implements the AI analyst layer: it looks at aggregated
// traffic, near-miss signals and incidents through read-only tools, and
// produces structured findings with recommendations. It never sits in the
// detection or mitigation fast path and never applies changes itself.
package analyst

import (
	"context"
	"encoding/json"
)

// FlowSpecHint is a simplified FlowSpec recommendation.
type FlowSpecHint struct {
	Target          string  `json:"target"`
	Direction       string  `json:"direction,omitempty"`
	Protocol        string  `json:"protocol,omitempty"`
	SrcPorts        []int   `json:"src_ports,omitempty"`
	DstPorts        []int   `json:"dst_ports,omitempty"`
	MinPacketLength int     `json:"min_packet_length,omitempty"`
	Action          string  `json:"action,omitempty"`
	RateBps         float64 `json:"rate_bps,omitempty"`
}

// ThresholdHint is a threshold change recommendation.
type ThresholdHint struct {
	RuleID  string  `json:"rule_id"`
	Profile string  `json:"profile,omitempty"`
	PPS     float64 `json:"pps,omitempty"`
	BPS     float64 `json:"bps,omitempty"`
}

// Recommendation is an actionable suggestion (always requires human approval).
type Recommendation struct {
	Type      string         `json:"type"` // threshold_change | new_rule | flowspec | scrub | rtbh | whitelist | investigate | no_action
	Title     string         `json:"title"`
	Detail    string         `json:"detail"`
	RuleID    string         `json:"rule_id,omitempty"`
	FlowSpec  *FlowSpecHint  `json:"flowspec,omitempty"`
	Threshold *ThresholdHint `json:"threshold,omitempty"`
	Applied   string         `json:"applied,omitempty"` // mitigation id once applied from the UI
}

// EvidenceItem ties a claim to the tool output that supports it.
type EvidenceItem struct {
	Claim  string `json:"claim"`
	Source string `json:"source"`
}

// TraceStep records one tool call (shown in the UI for transparency).
type TraceStep struct {
	Turn       int    `json:"turn"`
	Tool       string `json:"tool"`
	Input      string `json:"input"`
	Output     string `json:"output_preview"`
	IsError    bool   `json:"is_error,omitempty"`
	DurationMs int64  `json:"duration_ms"`
}

// Usage reports model token usage.
type Usage struct {
	Turns        int   `json:"turns"`
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
	CacheRead    int64 `json:"cache_read_tokens,omitempty"`
}

// Finding is the analyst's structured output.
type Finding struct {
	ID              string           `json:"id"`
	CreatedAt       int64            `json:"created_at"`
	DurationMs      int64            `json:"duration_ms"`
	Mode            string           `json:"mode"` // signals | incident | question
	Provider        string           `json:"provider"`
	Model           string           `json:"model"`
	Status          string           `json:"status"` // ok | error
	Error           string           `json:"error,omitempty"`
	Question        string           `json:"question,omitempty"`
	IncidentID      string           `json:"incident_id,omitempty"`
	SignalIDs       []string         `json:"signal_ids,omitempty"`
	Title           string           `json:"title"`
	Summary         string           `json:"summary"`
	Classification  string           `json:"classification"`
	Severity        string           `json:"severity"`
	Confidence      float64          `json:"confidence"`
	Targets         []string         `json:"targets,omitempty"`
	Hypothesis      string           `json:"hypothesis,omitempty"`
	MissedReason    string           `json:"missed_reason,omitempty"`
	Evidence        []EvidenceItem   `json:"evidence"`
	Recommendations []Recommendation `json:"recommendations"`
	Trace           []TraceStep      `json:"trace"`
	Usage           Usage            `json:"usage"`
}

// Tool is a provider-agnostic tool definition.
type Tool struct {
	Name        string
	Description string
	Properties  map[string]any
	Required    []string
	Run         func(ctx context.Context, input json.RawMessage) (any, error)
}

// Executor runs a tool call and returns (result text, isError, finished).
// finished is true once submit_finding was accepted.
type Executor func(ctx context.Context, turn int, name string, input json.RawMessage) (string, bool, bool)

// Provider runs the agent loop with a model.
type Provider interface {
	Name() string
	Model() string
	Run(ctx context.Context, system, user string, tools []Tool, maxTurns int, exec Executor) (Usage, error)
}
