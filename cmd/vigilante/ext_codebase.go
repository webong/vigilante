//go:build !nocodebase

package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"

	"github.com/webong/ext/res/system/graph"
	"github.com/webong/vigilante/ext/agent"
	"github.com/webong/vigilante/ext/codebase"
)

const codebaseExtName = "codebase"

func init() {
	registerFeatureExtension(codebaseFeatureExt{})
}

type codebaseFeatureExt struct{}

func (codebaseFeatureExt) Name() string        { return codebaseExtName }
func (codebaseFeatureExt) KnownKeys() []string { return codebase.KnownKeys() }

func (codebaseFeatureExt) BindFlags(fs *flag.FlagSet) FlagBinding {
	return codebaseFlagBinding{flags: codebase.BindFlags(fs)}
}

func (codebaseFeatureExt) DecodeJSON(raw map[string]json.RawMessage, cfg *Config) error {
	cb := codebaseConfig(*cfg)
	if err := codebase.DecodeJSON(raw, &cb); err != nil {
		return err
	}
	cfg.SetExtension(codebaseExtName, cb)
	return nil
}

func (codebaseFeatureExt) DecodeYAML(key, val string, captureBlock func() (string, error), cfg *Config) (bool, error) {
	cb := codebaseConfig(*cfg)
	handled, err := codebase.DecodeYAML(key, val, captureBlock, &cb)
	if err != nil {
		return true, err
	}
	if handled {
		cfg.SetExtension(codebaseExtName, cb)
		return true, nil
	}
	return false, nil
}

func (codebaseFeatureExt) Merge(dst, src *Config, keys map[string]bool) {
	d := codebaseConfig(*dst)
	s := codebaseConfig(*src)
	codebase.Merge(&d, s, keys)
	dst.SetExtension(codebaseExtName, d)
}

type codebaseFlagBinding struct {
	flags *codebase.FlagState
}

func (b codebaseFlagBinding) Apply(set map[string]bool, cfg *Config) {
	cb := codebase.Resolve(set, b.flags, codebaseConfig(*cfg))
	cfg.SetExtension(codebaseExtName, cb)
}

func codebaseConfig(cfg Config) codebase.Config {
	if v, ok := cfg.Extension(codebaseExtName); ok {
		if cb, ok := v.(codebase.Config); ok {
			return cb
		}
	}
	return codebase.Config{}
}

func openCodebase(ctx context.Context, out io.Writer, cfg *Config, mode, target string, store graph.Store) (agent.CodebaseService, func(context.Context) error, error) {
	if !hasFeatureExtension(codebaseExtName) {
		return nil, nil, nil
	}
	return codebase.OpenFromConfig(ctx, out, codebaseConfig(*cfg), mode, target, store)
}
