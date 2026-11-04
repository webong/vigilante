package lookout

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/webong/ext/pkg/ext-go/engine"
	"github.com/webong/ext/pkg/ext-go/engine/guest/author"
	"github.com/webong/vigilante/ext/triage"
	"github.com/webong/vigilante/internal/action"
	"github.com/webong/vigilante/internal/history"
)

// errNoHost is returned when a guest handler runs without the console
// contract, e.g. when the host offered no reverse calls.
var errNoHost = errors.New("lookout: host does not offer vigilante.console@v1")

// reverseHost implements Host inside the guest by calling the host back on
// the session of the request in flight.
type reverseHost struct{}

func call[In, Out any](ctx context.Context, m author.Method[In, Out], in In) (Out, error) {
	caller := engine.ReverseFrom(ctx)
	if caller == nil {
		var zero Out
		return zero, errNoHost
	}
	return author.Call(ctx, caller, m, in)
}

func (reverseHost) Actors(ctx context.Context, limit int) ([]history.Actor, error) {
	out, err := call(ctx, opActors, ActorsIn{Limit: limit})
	return out.Actors, err
}

func (reverseHost) Flows(ctx context.Context, key string, since time.Time, limit int) ([]history.Flow, error) {
	out, err := call(ctx, opFlows, FlowsIn{ActorKey: key, Since: since, Limit: limit})
	return out.Flows, err
}

func (reverseHost) Egress(ctx context.Context, since time.Time, limit int) ([]history.Egress, error) {
	out, err := call(ctx, opEgress, EgressIn{Since: since, Limit: limit})
	return out.Egress, err
}

func (reverseHost) Suggestions(ctx context.Context, status string) ([]history.Suggestion, error) {
	out, err := call(ctx, opSuggestions, SuggestionsIn{Status: status})
	return out.Suggestions, err
}

func (reverseHost) Suggest(ctx context.Context, s history.Suggestion) error {
	_, err := call(ctx, opSuggest, SuggestIn{Suggestion: s})
	return err
}

func (reverseHost) ResolveSuggestion(ctx context.Context, id, status, decisionID string) (history.Suggestion, error) {
	return call(ctx, opResolve, ResolveIn{ID: id, Status: status, DecisionID: decisionID})
}

func (reverseHost) Execute(ctx context.Context, req action.Request) (action.Decision, error) {
	return call(ctx, opExecute, req)
}

func (reverseHost) Revert(ctx context.Context, id string) (action.Decision, error) {
	return call(ctx, opRevert, RevertIn{DecisionID: id})
}

func (reverseHost) TriageModel(ctx context.Context) (string, error) {
	out, err := call(ctx, opTriageModel, Empty{})
	return out.Model, err
}

func (reverseHost) Triage(ctx context.Context, in triage.Input) (triage.Verdict, error) {
	return call(ctx, opTriage, in)
}

// hostReverseOptions serves vigilante.console@v1 from h on the host side.
func hostReverseOptions(h Host) *engine.ReverseOptions {
	ref := engine.ContractRef{Name: ConsoleContractName, Version: ConsoleContractVersion}
	ops := map[string]bool{}
	for _, op := range consoleOperations() {
		ops[op.Name] = true
	}
	return &engine.ReverseOptions{
		MaxPayloadBytes: MaxReversebytes,
		Authorize: func(_ context.Context, req engine.Request) error {
			if req.Contract == ref && ops[req.Operation] {
				return nil
			}
			return engine.ErrDenied
		},
		Handle: func(ctx context.Context, req engine.Request) (json.RawMessage, error) {
			switch req.Operation {
			case opActors.Operation.Name:
				return serve(req, func(in ActorsIn) (ActorsOut, error) {
					a, err := h.Actors(ctx, in.Limit)
					return ActorsOut{Actors: a}, err
				})
			case opFlows.Operation.Name:
				return serve(req, func(in FlowsIn) (FlowsOut, error) {
					f, err := h.Flows(ctx, in.ActorKey, in.Since, in.Limit)
					return FlowsOut{Flows: f}, err
				})
			case opEgress.Operation.Name:
				return serve(req, func(in EgressIn) (EgressOut, error) {
					e, err := h.Egress(ctx, in.Since, in.Limit)
					return EgressOut{Egress: e}, err
				})
			case opSuggestions.Operation.Name:
				return serve(req, func(in SuggestionsIn) (SuggestionsOut, error) {
					s, err := h.Suggestions(ctx, in.Status)
					return SuggestionsOut{Suggestions: s}, err
				})
			case opSuggest.Operation.Name:
				return serve(req, func(in SuggestIn) (Empty, error) { return Empty{}, h.Suggest(ctx, in.Suggestion) })
			case opResolve.Operation.Name:
				return serve(req, func(in ResolveIn) (history.Suggestion, error) {
					return h.ResolveSuggestion(ctx, in.ID, in.Status, in.DecisionID)
				})
			case opExecute.Operation.Name:
				return serve(req, func(in action.Request) (action.Decision, error) { return h.Execute(ctx, in) })
			case opRevert.Operation.Name:
				return serve(req, func(in RevertIn) (action.Decision, error) { return h.Revert(ctx, in.DecisionID) })
			case opTriageModel.Operation.Name:
				return serve(req, func(Empty) (TriageModelOut, error) {
					m, err := h.TriageModel(ctx)
					return TriageModelOut{Model: m}, err
				})
			case opTriage.Operation.Name:
				return serve(req, func(in triage.Input) (triage.Verdict, error) { return h.Triage(ctx, in) })
			}
			return nil, &engine.RemoteError{Code: "unsupported", Message: "unknown console operation"}
		},
	}
}

func serve[In, Out any](req engine.Request, fn func(In) (Out, error)) (json.RawMessage, error) {
	var in In
	if err := engine.Decode(req.Payload, &in); err != nil {
		return nil, &engine.RemoteError{Code: "invalid_input", Message: "invalid console input"}
	}
	out, err := fn(in)
	if err != nil {
		// Host errors (validation, policy denials) are operator-facing; pass the
		// message through rather than collapsing it to a generic failure.
		msg := err.Error()
		if len(msg) > 1024 {
			msg = msg[:1024]
		}
		return nil, &engine.RemoteError{Code: "failed", Message: msg}
	}
	return json.Marshal(out)
}
