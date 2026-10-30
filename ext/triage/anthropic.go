// Package triage
package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

type anthropicProvider struct {
	apiKey string
	model  string
	effort string
	client *http.Client
}

// NewAnthropic returns a Provider that triages with Claude through the
// Anthropic Messages API.
//
// It uses tool_choice so the model returns the verdict as a structured
// tool_call input, avoiding the official SDK.
func NewAnthropic(apiKey, model, effort string) Provider {
	return &anthropicProvider{
		apiKey: apiKey,
		model:  model,
		effort: effort,
		client: &http.Client{Timeout: 3 * time.Minute},
	}
}

type anthroMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthroTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

type anthroToolChoice struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type anthroRequest struct {
	Model      string            `json:"model"`
	MaxTokens  int               `json:"max_tokens"`
	System     string            `json:"system"`
	Messages   []anthroMessage   `json:"messages"`
	Tools      []anthroTool      `json:"tools,omitempty"`
	ToolChoice *anthroToolChoice `json:"tool_choice,omitempty"`
}

type anthroResponse struct {
	ID         string `json:"id"`
	Model      string `json:"model"`
	StopReason string `json:"stop_reason"`
	Content    []struct {
		Type    string `json:"type"`
		Text    string `json:"text"`
		ToolUse *struct {
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"tool_use"`
	} `json:"content"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

func (p *anthropicProvider) Complete(ctx context.Context, system, user string, schema json.RawMessage) (string, string, error) {
	req := anthroRequest{
		Model:     p.model,
		MaxTokens: 16000,
		System:    system,
		Messages:  []anthroMessage{{Role: "user", Content: user}},
		Tools: []anthroTool{{
			Name:        "verdict",
			Description: "Emit the actor triage verdict as structured output.",
			InputSchema: schema,
		}},
		ToolChoice: &anthroToolChoice{Type: "tool", Name: "verdict"},
	}

	body, err := json.Marshal(req)
	if err != nil {
		return "", "", err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	httpReq.Header.Set("x-api-key", p.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("anthropic-version", "2023-06-01")
	httpReq.Header.Set("anthropic-beta", "max-tokens-3-5-sonnet-2024-07-15")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	var out anthroResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out); err != nil {
		return "", "", fmt.Errorf("anthropic: %s: unreadable response: %w", resp.Status, err)
	}
	if out.Error != nil {
		return "", "", fmt.Errorf("anthropic: %s: %s", resp.Status, out.Error.Message)
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("anthropic: %s", resp.Status)
	}
	for _, block := range out.Content {
		if block.Type == "tool_use" && block.ToolUse != nil && block.ToolUse.Name == "verdict" {
			return string(block.ToolUse.Input), out.Model, nil
		}
		if block.Type == "text" && block.Text != "" {
			// Some Claude variants ignore tool_choice and return text.
			return block.Text, out.Model, nil
		}
	}
	if out.StopReason == "refusal" {
		return "", "", errors.New("model declined to triage this actor")
	}
	return "", "", errors.New("anthropic: no verdict tool_use in response")
}
