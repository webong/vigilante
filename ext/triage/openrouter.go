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
	"strings"
	"time"
)

// OpenRouterURL is OpenRouter's OpenAI-compatible API base.
const OpenRouterURL = "https://openrouter.ai/api/v1"

type openRouterProvider struct {
	baseURL string
	apiKey  string
	model   string
	effort  string
	client  *http.Client
}

// NewOpenRouter returns a Provider that triages through OpenRouter's chat
// completions API.
func NewOpenRouter(baseURL, apiKey, model, effort string) Provider {
	return &openRouterProvider{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		model:   model,
		effort:  effort,
		client:  &http.Client{Timeout: 3 * time.Minute},
	}
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model          string        `json:"model"`
	Messages       []chatMessage `json:"messages"`
	MaxTokens      int           `json:"max_tokens"`
	ResponseFormat struct {
		Type       string `json:"type"`
		JSONSchema struct {
			Name   string          `json:"name"`
			Strict bool            `json:"strict"`
			Schema json.RawMessage `json:"schema"`
		} `json:"json_schema"`
	} `json:"response_format"`
	Reasoning *struct {
		Effort string `json:"effort"`
	} `json:"reasoning,omitempty"`
	Provider struct {
		RequireParameters bool `json:"require_parameters"`
	} `json:"provider"`
}

type apiError struct {
	Message string `json:"message"`
	Code    any    `json:"code"`
}

type chatResponse struct {
	Model   string    `json:"model"`
	Error   *apiError `json:"error"`
	Choices []struct {
		FinishReason string    `json:"finish_reason"`
		Error        *apiError `json:"error"`
		Message      struct {
			Content string `json:"content"`
			Refusal string `json:"refusal"`
		} `json:"message"`
	} `json:"choices"`
}

func (p *openRouterProvider) Complete(ctx context.Context, system, user string, schema json.RawMessage) (string, string, error) {
	req := chatRequest{
		Model:     p.model,
		Messages:  []chatMessage{{Role: "system", Content: system}, {Role: "user", Content: user}},
		MaxTokens: 16000,
	}
	req.ResponseFormat.Type = "json_schema"
	req.ResponseFormat.JSONSchema.Name = "verdict"
	req.ResponseFormat.JSONSchema.Strict = true
	req.ResponseFormat.JSONSchema.Schema = schema
	if p.effort != "" {
		req.Reasoning = &struct {
			Effort string `json:"effort"`
		}{p.effort}
	}
	req.Provider.RequireParameters = true

	body, err := json.Marshal(req)
	if err != nil {
		return "", "", err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Title", "vigilante")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	var out chatResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out); err != nil {
		return "", "", fmt.Errorf("openrouter: %s: unreadable response: %w", resp.Status, err)
	}
	if out.Error != nil {
		return "", "", fmt.Errorf("openrouter: %s: %s", resp.Status, out.Error.Message)
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("openrouter: %s", resp.Status)
	}
	if len(out.Choices) == 0 {
		return "", "", errors.New("openrouter: no choices in response")
	}
	c := out.Choices[0]
	switch {
	case c.Error != nil:
		return "", "", fmt.Errorf("openrouter: %s", c.Error.Message)
	case c.Message.Refusal != "":
		return "", "", errors.New("model declined to triage this actor")
	case c.FinishReason == "length":
		return "", "", errors.New("openrouter: reply cut off at max_tokens")
	case strings.TrimSpace(c.Message.Content) == "":
		return "", "", fmt.Errorf("openrouter: empty reply (finish_reason %q)", c.FinishReason)
	}
	return c.Message.Content, out.Model, nil
}
