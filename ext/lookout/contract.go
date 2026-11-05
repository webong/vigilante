// Package lookout is Vigilante's operator console, shipped as an ext.plugin/v1
// plugin rather than as part of the core (ADR 0003, ADR 0005).
//
// Two contracts meet here:
//
//   - vigilante.lookout@v1 is what the guest implements: serve-http takes one
//     HTTP request the host received under /lookout/ and returns the response.
//     The guest owns the UI, its assets, operator login and sessions.
//   - vigilante.console@v1 is what the host implements and offers to the guest
//     as reverse calls: actor history, the review queue, egress, LLM actor
//     triage, and action execution. Every action still goes through the host's
//     action.Registry, so the console holds no authority of its own.
//
// The console is first-party; its contract reuses core types. A third-party
// console builds on the REST data API (/obs/*) instead.
package lookout

import (
	"context"
	"time"

	"github.com/webong/ext/pkg/ext-go/engine"
	"github.com/webong/ext/pkg/ext-go/engine/guest/author"
	"github.com/webong/vigilante/ext/triage"
	"github.com/webong/vigilante/internal/action"
	"github.com/webong/vigilante/internal/history"
)

const (
	ContractName       = "vigilante.lookout"
	ContractVersion    = "v1"
	OperationServeHTTP = "serve-http"

	ConsoleContractName    = "vigilante.console"
	ConsoleContractVersion = "v1"
)

// Bounds on what crosses the session.
const (
	MaxRequestBody  = 1 << 20
	MaxReversebytes = 16 << 20 // actor detail and egress lists can be large
)

// HTTPRequest is one request the host forwards. Only the headers the console
// needs are copied.
type HTTPRequest struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"` // relative to the mount, always starts with "/"
	Query   string            `json:"query,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    []byte            `json:"body,omitempty"`
	TLS     bool              `json:"tls,omitempty"`
}

// HTTPResponse is the guest's answer.
type HTTPResponse struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    []byte            `json:"body,omitempty"`
}

// forwardedHeaders are the request headers the host passes to the guest.
var forwardedHeaders = []string{
	"Accept", "Accept-Encoding", "Authorization", "Content-Type", "Cookie",
	"If-Modified-Since", "If-None-Match", "Origin", "Range", "X-Vigilante-Token",
}

// Host is what the console needs from Vigilante. The host implements it over
// core; inside the guest it is satisfied by reverse calls.
type Host interface {
	Actors(ctx context.Context, limit int) ([]history.Actor, error)
	Flows(ctx context.Context, actorKey string, since time.Time, limit int) ([]history.Flow, error)
	Egress(ctx context.Context, since time.Time, limit int) ([]history.Egress, error)
	Suggestions(ctx context.Context, status string) ([]history.Suggestion, error)
	Suggest(ctx context.Context, s history.Suggestion) error
	ResolveSuggestion(ctx context.Context, id, status, decisionID string) (history.Suggestion, error)
	Execute(ctx context.Context, req action.Request) (action.Decision, error)
	Revert(ctx context.Context, decisionID string) (action.Decision, error)
	// TriageModel is "" when LLM actor triage is not configured.
	TriageModel(ctx context.Context) (string, error)
	Triage(ctx context.Context, in triage.Input) (triage.Verdict, error)
	Sensors(ctx context.Context) ([]history.Sensor, error)
	CreateSensor(ctx context.Context, name string) (CreatedSensor, error)
	DeleteSensor(ctx context.Context, id int64) error
}

// Reverse-call payloads.
type (
	ActorsIn struct {
		Limit int `json:"limit"`
	}
	ActorsOut struct {
		Actors []history.Actor `json:"actors"`
	}
	FlowsIn struct {
		ActorKey string    `json:"actor_key"`
		Since    time.Time `json:"since"`
		Limit    int       `json:"limit"`
	}
	FlowsOut struct {
		Flows []history.Flow `json:"flows"`
	}
	EgressIn struct {
		Since time.Time `json:"since"`
		Limit int       `json:"limit"`
	}
	EgressOut struct {
		Egress []history.Egress `json:"egress"`
	}
	SuggestionsIn struct {
		Status string `json:"status"`
	}
	SuggestionsOut struct {
		Suggestions []history.Suggestion `json:"suggestions"`
	}
	SuggestIn struct {
		Suggestion history.Suggestion `json:"suggestion"`
	}
	ResolveIn struct {
		ID         string `json:"id"`
		Status     string `json:"status"`
		DecisionID string `json:"decision_id,omitempty"`
	}
	RevertIn struct {
		DecisionID string `json:"decision_id"`
	}
	TriageModelOut struct {
		Model string `json:"model"`
	}
	SensorsOut struct {
		Sensors []history.Sensor `json:"sensors"`
	}
	CreateSensorIn struct {
		Name string `json:"name"`
	}
	CreatedSensor struct {
		Sensor history.Sensor `json:"sensor"`
		Key    string         `json:"key"`
	}
	DeleteSensorIn struct {
		ID int64 `json:"id"`
	}
	Empty struct{}
)

func ServeHTTPMethod() author.Method[HTTPRequest, HTTPResponse] {
	return author.Method[HTTPRequest, HTTPResponse]{
		Contract:  engine.ContractRef{Name: ContractName, Version: ContractVersion},
		Operation: engine.Operation{Name: OperationServeHTTP, Surface: "console"},
	}
}

func consoleMethod[In, Out any](op string) author.Method[In, Out] {
	return author.Method[In, Out]{
		Contract:  engine.ContractRef{Name: ConsoleContractName, Version: ConsoleContractVersion},
		Operation: engine.Operation{Name: op, Surface: "console"},
	}
}

// Console operations, offered by the host.
var (
	opActors       = consoleMethod[ActorsIn, ActorsOut]("actors")
	opFlows        = consoleMethod[FlowsIn, FlowsOut]("flows")
	opEgress       = consoleMethod[EgressIn, EgressOut]("egress")
	opSuggestions  = consoleMethod[SuggestionsIn, SuggestionsOut]("suggestions")
	opSuggest      = consoleMethod[SuggestIn, Empty]("suggest")
	opResolve      = consoleMethod[ResolveIn, history.Suggestion]("resolve-suggestion")
	opExecute      = consoleMethod[action.Request, action.Decision]("execute-action")
	opRevert       = consoleMethod[RevertIn, action.Decision]("revert-action")
	opTriageModel  = consoleMethod[Empty, TriageModelOut]("triage-model")
	opTriage       = consoleMethod[triage.Input, triage.Verdict]("triage-actor")
	opSensors      = consoleMethod[Empty, SensorsOut]("sensors")
	opCreateSensor = consoleMethod[CreateSensorIn, CreatedSensor]("create-sensor")
	opDeleteSensor = consoleMethod[DeleteSensorIn, Empty]("delete-sensor")
)

func consoleOperations() []engine.Operation {
	return []engine.Operation{
		opActors.Operation, opFlows.Operation, opEgress.Operation,
		opSuggestions.Operation, opSuggest.Operation, opResolve.Operation,
		opExecute.Operation, opRevert.Operation,
		opTriageModel.Operation, opTriage.Operation,
		opSensors.Operation, opCreateSensor.Operation, opDeleteSensor.Operation,
	}
}

// GuestIdentity identifies the lookout guest.
func GuestIdentity() engine.Identity {
	return engine.Identity{ID: "vigilante/lookout", Revision: "v1.0.0", Version: "1.0.0"}
}
