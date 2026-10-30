package history

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/webong/vigilante/internal/flow"
)

type Actor struct {
	Key         string    `json:"key"`
	IP          string    `json:"ip"`
	Fingerprint string    `json:"tls_fingerprint,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Requests    int       `json:"requests"`
	Class       string    `json:"class"`
	Risk        int       `json:"risk"`
	Signals     []string  `json:"signals"`
	Identity    string    `json:"identity,omitempty"`
}

func (s *Store) Actors(ctx context.Context, limit int) ([]Actor, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT key,ip,fingerprint,user_agent,first_seen,last_seen,requests,class,risk,signals,identity FROM actors ORDER BY risk DESC,last_seen DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Actor{}
	for rows.Next() {
		var a Actor
		var first, last int64
		var signals string
		if err := rows.Scan(&a.Key, &a.IP, &a.Fingerprint, &a.UserAgent, &first, &last, &a.Requests, &a.Class, &a.Risk, &signals, &a.Identity); err != nil {
			return nil, err
		}
		a.FirstSeen = time.UnixMilli(first).UTC()
		a.LastSeen = time.UnixMilli(last).UTC()
		a.Signals = []string{}
		_ = json.Unmarshal([]byte(signals), &a.Signals)
		out = append(out, a)
	}
	return out, rows.Err()
}
func (s *Store) Actor(ctx context.Context, key string) (Actor, error) {
	var a Actor
	var first, last int64
	var signals string
	err := s.db.QueryRowContext(ctx, `SELECT key,ip,fingerprint,user_agent,first_seen,last_seen,requests,class,risk,signals,identity FROM actors WHERE key=?`, key).Scan(&a.Key, &a.IP, &a.Fingerprint, &a.UserAgent, &first, &last, &a.Requests, &a.Class, &a.Risk, &signals, &a.Identity)
	if err != nil {
		return a, err
	}
	a.FirstSeen = time.UnixMilli(first).UTC()
	a.LastSeen = time.UnixMilli(last).UTC()
	a.Signals = []string{}
	_ = json.Unmarshal([]byte(signals), &a.Signals)
	return a, nil
}

type Flow struct {
	flow.Event
	ActorKey string `json:"actor_key"`
}

func (s *Store) Flows(ctx context.Context, key string, since time.Time, limit int) ([]Flow, error) {
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	args := []any{}
	q := `SELECT id,actor_key,ts,severity,verdict,summary,method,path,src,target,protocol,host,user_agent,fingerprint,headers,status,duration_ns,bytes_in,bytes_out FROM flows`
	if key != "" {
		q += ` WHERE actor_key=?`
		args = append(args, key)
		if !since.IsZero() {
			q += ` AND ts>=?`
			args = append(args, since.UnixMilli())
		}
	} else if !since.IsZero() {
		q += ` WHERE ts>=?`
		args = append(args, since.UnixMilli())
	}
	q += ` ORDER BY ts DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Flow{}
	for rows.Next() {
		var f Flow
		var ts, dur int64
		var headers string
		if err := rows.Scan(&f.FlowID, &f.ActorKey, &ts, &f.Severity, &f.Verdict, &f.Summary, &f.Method, &f.Path, &f.SrcAddr, &f.TargetAddr, &f.Protocol, &f.Host, &f.UserAgent, &f.TLSFingerprint, &headers, &f.Status, &dur, &f.BytesIn, &f.BytesOut); err != nil {
			return nil, err
		}
		f.Timestamp = time.UnixMilli(ts).UTC()
		f.Duration = time.Duration(dur)
		_ = json.Unmarshal([]byte(headers), &f.Headers)
		out = append(out, f)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, rows.Err()
}
func (s *Store) Analyze(ctx context.Context, a Actor) error {
	signals, _ := json.Marshal(a.Signals)
	_, err := s.db.ExecContext(ctx, `UPDATE actors SET class=?,risk=?,signals=?,identity=? WHERE key=?`, a.Class, a.Risk, signals, a.Identity, a.Key)
	return err
}

var ErrNotFound = sql.ErrNoRows
