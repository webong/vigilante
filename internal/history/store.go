// Package history is the optional durable evidence store. It is a flow sink,
// never a request-path dependency; detectors query it asynchronously.
package history

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/webong/vigilante/internal/actor"
	"github.com/webong/vigilante/internal/decision"
	"github.com/webong/vigilante/internal/flow"
)

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("history: path is required")
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_txlock=immediate&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("history schema: %w", err)
	}
	return &Store{db: db}, nil
}
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	return s.db.Close()
}

const schema = `CREATE TABLE IF NOT EXISTS actors (
 key TEXT PRIMARY KEY, ip TEXT NOT NULL, fingerprint TEXT NOT NULL DEFAULT '', user_agent TEXT NOT NULL DEFAULT '',
 first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, requests INTEGER NOT NULL DEFAULT 0,
 class TEXT NOT NULL DEFAULT 'unknown', risk INTEGER NOT NULL DEFAULT 0, signals TEXT NOT NULL DEFAULT '[]', identity TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS flows (
 id TEXT PRIMARY KEY, actor_key TEXT NOT NULL REFERENCES actors(key) ON DELETE CASCADE, ts INTEGER NOT NULL,
 severity TEXT NOT NULL, verdict TEXT NOT NULL, summary TEXT NOT NULL DEFAULT '', method TEXT NOT NULL DEFAULT '',
 path TEXT NOT NULL DEFAULT '', src TEXT NOT NULL DEFAULT '', target TEXT NOT NULL DEFAULT '', protocol TEXT NOT NULL DEFAULT '',
 host TEXT NOT NULL DEFAULT '', user_agent TEXT NOT NULL DEFAULT '', fingerprint TEXT NOT NULL DEFAULT '',
 headers TEXT NOT NULL DEFAULT '{}', status INTEGER NOT NULL DEFAULT 0, duration_ns INTEGER NOT NULL DEFAULT 0,
 bytes_in INTEGER NOT NULL DEFAULT 0, bytes_out INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS flows_actor_ts ON flows(actor_key, ts);
CREATE INDEX IF NOT EXISTS flows_ts ON flows(ts);
CREATE TABLE IF NOT EXISTS suggestions (
 id TEXT PRIMARY KEY, actor_key TEXT NOT NULL, action TEXT NOT NULL, scope TEXT NOT NULL, target TEXT NOT NULL,
 reason TEXT NOT NULL, created_at INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
 decision_id TEXT NOT NULL DEFAULT '', resolved_at INTEGER
);
CREATE INDEX IF NOT EXISTS suggestions_status ON suggestions(status, created_at);
CREATE TABLE IF NOT EXISTS egress (
 id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, comm TEXT NOT NULL, pid INTEGER NOT NULL,
 uid INTEGER NOT NULL, dst_ip TEXT NOT NULL, dst_port INTEGER NOT NULL, count INTEGER NOT NULL,
 UNIQUE(ts, comm, pid, uid, dst_ip, dst_port) ON CONFLICT REPLACE
);
CREATE INDEX IF NOT EXISTS egress_ts ON egress(ts);`

// Ingest persists one flow and updates its actor atomically.
func (s *Store) Ingest(ctx context.Context, ev flow.Event) error {
	if s == nil {
		return nil
	}
	ts := ev.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	ip := decision.NormalizeIP(ev.SrcAddr)
	key := actor.ActorKey(ev.SrcAddr, ev.TLSFingerprint)
	headers, _ := json.Marshal(ev.Headers)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO actors(key,ip,fingerprint,user_agent,first_seen,last_seen,requests) VALUES(?,?,?,?,?,?,1)
 ON CONFLICT(key) DO UPDATE SET last_seen=excluded.last_seen,requests=requests+1,
 ip=excluded.ip,fingerprint=excluded.fingerprint,user_agent=CASE WHEN excluded.user_agent='' THEN actors.user_agent ELSE excluded.user_agent END`,
		key, ip, ev.TLSFingerprint, ev.UserAgent, ts.UnixMilli(), ts.UnixMilli()); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO flows(id,actor_key,ts,severity,verdict,summary,method,path,src,target,protocol,host,user_agent,fingerprint,headers,status,duration_ns,bytes_in,bytes_out)
 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`, ev.FlowID, key, ts.UnixMilli(), ev.Severity, ev.Verdict, ev.Summary, ev.Method, ev.Path, ev.SrcAddr, ev.TargetAddr, ev.Protocol, ev.Host, ev.UserAgent, ev.TLSFingerprint, headers, ev.Status, ev.Duration, ev.BytesIn, ev.BytesOut)
	if err != nil {
		return err
	}
	return tx.Commit()
}
