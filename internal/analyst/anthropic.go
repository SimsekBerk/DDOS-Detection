package analyst

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/anthropics/anthropic-sdk-go/packages/param"
	"github.com/anthropics/anthropic-sdk-go/shared/constant"
)

// anthropicProvider runs the agent loop on the Claude API (official Go SDK).
type anthropicProvider struct {
	client    anthropic.Client
	model     string
	effort    string
	maxTokens int64
}

func newAnthropic(model, effort string, maxTokens int) *anthropicProvider {
	// Credentials are read from ANTHROPIC_API_KEY by the SDK.
	return &anthropicProvider{
		client:    anthropic.NewClient(option.WithMaxRetries(2)),
		model:     model,
		effort:    effort,
		maxTokens: int64(maxTokens),
	}
}

func (p *anthropicProvider) Name() string  { return "anthropic" }
func (p *anthropicProvider) Model() string { return p.model }

func (p *anthropicProvider) Run(ctx context.Context, system, user string, tools []Tool, maxTurns int, exec Executor) (Usage, error) {
	var usage Usage
	var toolParams []anthropic.BetaToolUnionParam
	for _, t := range tools {
		tp := anthropic.BetaToolParam{
			Name:        t.Name,
			Description: param.NewOpt(t.Description),
			InputSchema: anthropic.BetaToolInputSchemaParam{Properties: t.Properties, Required: t.Required},
		}
		toolParams = append(toolParams, anthropic.BetaToolUnionParam{OfTool: &tp})
	}
	messages := []anthropic.BetaMessageParam{anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(user))}
	nudged := false
	for turn := 1; turn <= maxTurns; turn++ {
		params := anthropic.BetaMessageNewParams{
			Model:     p.model,
			MaxTokens: p.maxTokens,
			// System + tools are stable across turns and runs: cache them.
			System:   []anthropic.BetaTextBlockParam{{Text: system, CacheControl: anthropic.NewBetaCacheControlEphemeralParam()}},
			Messages: messages,
			Tools:    toolParams,
			Thinking: anthropic.BetaThinkingConfigParamUnion{OfAdaptive: &anthropic.BetaThinkingConfigAdaptiveParam{}},
			OutputConfig: anthropic.BetaOutputConfigParam{
				Effort: anthropic.BetaOutputConfigEffort(p.effort),
			},
			// Server-side fallback: if a request is declined by a safety
			// classifier, the API re-serves it with a suitable model.
			Betas:     []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01},
			Fallbacks: anthropic.BetaFallbacksParamUnion{OfDefault: constant.ValueOf[constant.Default]()},
		}
		resp, err := p.client.Beta.Messages.New(ctx, params)
		if err != nil {
			var apiErr *anthropic.Error
			if errors.As(err, &apiErr) {
				return usage, fmt.Errorf("Claude API hatası (%d): %s", apiErr.StatusCode, apiErr.Error())
			}
			return usage, err
		}
		usage.Turns = turn
		usage.InputTokens += resp.Usage.InputTokens
		usage.OutputTokens += resp.Usage.OutputTokens
		usage.CacheRead += resp.Usage.CacheReadInputTokens

		if resp.StopReason == anthropic.BetaStopReasonRefusal {
			return usage, fmt.Errorf("model isteği reddetti (kategori: %s)", resp.StopDetails.Category)
		}
		messages = append(messages, resp.ToParam())

		var results []anthropic.BetaContentBlockParamUnion
		finished := false
		for _, block := range resp.Content {
			if tu, ok := block.AsAny().(anthropic.BetaToolUseBlock); ok {
				out, isErr, done := exec(ctx, turn, tu.Name, json.RawMessage(tu.JSON.Input.Raw()))
				results = append(results, anthropic.NewBetaToolResultBlock(tu.ID, out, isErr))
				finished = finished || done
			}
		}
		if finished {
			return usage, nil
		}
		if resp.StopReason != anthropic.BetaStopReasonToolUse {
			if resp.StopReason == anthropic.BetaStopReasonMaxTokens {
				return usage, errors.New("yanıt max_tokens sınırına ulaştı")
			}
			if nudged {
				return usage, errors.New("model submit_finding çağırmadan bitirdi")
			}
			nudged = true
			messages = append(messages, anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(
				"Analizi submit_finding aracıyla yapılandırılmış bulgu olarak gönder.")))
			continue
		}
		if turn == maxTurns-1 {
			results = append(results, anthropic.NewBetaTextBlock("Araç bütçesi doldu. Şimdi elindeki kanıtlarla submit_finding çağır."))
		}
		messages = append(messages, anthropic.NewBetaUserMessage(results...))
	}
	return usage, errors.New("tur sınırına ulaşıldı, bulgu gönderilmedi")
}
