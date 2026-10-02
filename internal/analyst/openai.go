package analyst

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// openAICompatProvider talks to a local LLM server exposing the OpenAI
// chat-completions API with tool calling (Ollama, vLLM, LM Studio, llama.cpp
// server). Data never leaves the network when the server is local.
type openAICompatProvider struct {
	baseURL string
	model   string
	apiKey  string
	client  *http.Client
}

func newOpenAICompat(baseURL, model, apiKeyEnv string) *openAICompatProvider {
	key := ""
	if apiKeyEnv != "" {
		key = os.Getenv(apiKeyEnv)
	}
	return &openAICompatProvider{
		baseURL: strings.TrimRight(baseURL, "/"), model: model, apiKey: key,
		client: &http.Client{Timeout: 5 * time.Minute},
	}
}

func (p *openAICompatProvider) Name() string  { return "openai_compat" }
func (p *openAICompatProvider) Model() string { return p.model }

type oaMessage struct {
	Role       string       `json:"role"`
	Content    string       `json:"content"`
	ToolCalls  []oaToolCall `json:"tool_calls,omitempty"`
	ToolCallID string       `json:"tool_call_id,omitempty"`
}

type oaToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type oaResponse struct {
	Choices []struct {
		Message      oaMessage `json:"message"`
		FinishReason string    `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int64 `json:"prompt_tokens"`
		CompletionTokens int64 `json:"completion_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (p *openAICompatProvider) Run(ctx context.Context, system, user string, tools []Tool, maxTurns int, exec Executor) (Usage, error) {
	var usage Usage
	var toolDefs []map[string]any
	for _, t := range tools {
		params := map[string]any{"type": "object", "properties": t.Properties}
		if len(t.Required) > 0 {
			params["required"] = t.Required
		}
		toolDefs = append(toolDefs, map[string]any{
			"type":     "function",
			"function": map[string]any{"name": t.Name, "description": t.Description, "parameters": params},
		})
	}
	msgs := []oaMessage{{Role: "system", Content: system}, {Role: "user", Content: user}}
	nudged := false
	for turn := 1; turn <= maxTurns; turn++ {
		body, _ := json.Marshal(map[string]any{
			"model": p.model, "messages": msgs, "tools": toolDefs, "tool_choice": "auto", "temperature": 0.2,
		})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/chat/completions", bytes.NewReader(body))
		if err != nil {
			return usage, err
		}
		req.Header.Set("Content-Type", "application/json")
		if p.apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+p.apiKey)
		}
		resp, err := p.client.Do(req)
		if err != nil {
			return usage, fmt.Errorf("yerel LLM sunucusuna ulaşılamadı (%s): %w", p.baseURL, err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var out oaResponse
		if err := json.Unmarshal(raw, &out); err != nil {
			return usage, fmt.Errorf("yerel LLM geçersiz yanıt (%s): %.200s", resp.Status, raw)
		}
		if out.Error != nil {
			return usage, fmt.Errorf("yerel LLM hatası: %s", out.Error.Message)
		}
		if len(out.Choices) == 0 {
			return usage, errors.New("yerel LLM boş yanıt döndü")
		}
		usage.Turns = turn
		usage.InputTokens += out.Usage.PromptTokens
		usage.OutputTokens += out.Usage.CompletionTokens
		m := out.Choices[0].Message
		m.Role = "assistant"
		msgs = append(msgs, m)
		if len(m.ToolCalls) == 0 {
			if nudged {
				return usage, errors.New("model submit_finding çağırmadan bitirdi")
			}
			nudged = true
			msgs = append(msgs, oaMessage{Role: "user", Content: "Analizi submit_finding aracıyla yapılandırılmış bulgu olarak gönder."})
			continue
		}
		finished := false
		for _, tc := range m.ToolCalls {
			args := json.RawMessage(tc.Function.Arguments)
			if len(args) == 0 {
				args = json.RawMessage("{}")
			}
			res, _, done := exec(ctx, turn, tc.Function.Name, args)
			msgs = append(msgs, oaMessage{Role: "tool", ToolCallID: tc.ID, Content: res})
			finished = finished || done
		}
		if finished {
			return usage, nil
		}
		if turn == maxTurns-1 {
			msgs = append(msgs, oaMessage{Role: "user", Content: "Araç bütçesi doldu. Şimdi submit_finding çağır."})
		}
	}
	return usage, errors.New("tur sınırına ulaşıldı, bulgu gönderilmedi")
}
