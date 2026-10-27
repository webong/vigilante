// Package schema defines the vigilante.net consumer graph vocabulary on top of
// github.com/webong/ext/res/system/graph.
package schema

import (
	"fmt"

	"github.com/webong/ext/res/system/graph"
)

const (
	Namespace = "vigilante.net"
	Version   = "1"

	KindListener    = Namespace + "/listener"
	KindFlow        = Namespace + "/flow"
	KindProcessRef  = Namespace + "/process-ref"
	KindDependency  = Namespace + "/dependency"
	KindNetTopology = Namespace + "/network-topology"
	KindAgentAlert  = Namespace + "/agent-alert"

	RelAcceptsFlow   = Namespace + "/accepts-flow"
	RelOwnedBy       = Namespace + "/owned-by"
	RelDependsOn     = Namespace + "/depends-on"
	RelRoutesThrough = Namespace + "/routes-through"
	RelTriggered     = Namespace + "/triggered"
)

// Register registers the vigilante.net schema and relationship validator on store.
func Register(store graph.Store) error {
	return store.Register(graph.Schema{
		Namespace: Namespace,
		Version:   Version,
		Validate:  Validate,
	})
}

// Validate enforces vertex kinds and directed edge endpoint kinds within the
// vigilante.net namespace.
func Validate(view graph.View, tx graph.Transaction) error {
	allowedKinds := map[string]bool{
		KindListener:    true,
		KindFlow:        true,
		KindProcessRef:  true,
		KindDependency:  true,
		KindNetTopology: true,
		KindAgentAlert:  true,
	}
	for _, v := range tx.Vertices {
		if !allowedKinds[v.Kind] {
			return fmt.Errorf("unsupported %s vertex kind %q", Namespace, v.Kind)
		}
	}

	allowedRelations := map[string]struct{ from, to string }{
		RelAcceptsFlow:   {KindListener, KindFlow},
		RelOwnedBy:       {KindFlow, KindProcessRef},
		RelDependsOn:     {KindProcessRef, KindDependency},
		RelRoutesThrough: {KindFlow, KindNetTopology},
		RelTriggered:     {KindFlow, KindAgentAlert},
	}

	for _, e := range tx.Edges {
		expected, ok := allowedRelations[e.Type]
		if !ok {
			return fmt.Errorf("unsupported %s edge relationship %q", Namespace, e.Type)
		}
		from, fromOK := view.Vertex(Namespace, e.From)
		to, toOK := view.Vertex(Namespace, e.To)
		if !fromOK || !toOK {
			return graph.ErrDanglingEdge
		}
		if from.Kind != expected.from || to.Kind != expected.to {
			return fmt.Errorf("invalid endpoints for %q: got (%s -> %s), want (%s -> %s)",
				e.Type, from.Kind, to.Kind, expected.from, expected.to)
		}
	}
	return nil
}
