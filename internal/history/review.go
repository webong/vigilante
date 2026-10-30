package history

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/webong/vigilante/internal/decision"
)

type Suggestion struct {
	ID         string         `json:"id"`
	ActorKey   string         `json:"actor_key"`
	Action     string         `json:"action"`
	Scope      decision.Scope `json:"scope"`
	Target     string         `json:"target"`
	Reason     string         `json:"reason"`
	CreatedAt  time.Time      `json:"created_at"`
	Status     string         `json:"status"`
	DecisionID string         `json:"decision_id,omitempty"`
	ResolvedAt *time.Time     `json:"resolved_at,omitempty"`
}

func (s *Store) Suggest(ctx context.Context, v Suggestion) error {
	if v.ID == "" || v.ActorKey == "" || v.Action == "" {
		return fmt.Errorf("history: incomplete suggestion")
	}
	if v.CreatedAt.IsZero() {
		v.CreatedAt = time.Now()
	}
	if v.Status == "" {
		v.Status = "pending"
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO suggestions(id,actor_key,action,scope,target,reason,created_at,status)
 SELECT ?,?,?,?,?,?,?,? WHERE NOT EXISTS(SELECT 1 FROM suggestions WHERE actor_key=? AND status='pending')`,
		v.ID, v.ActorKey, v.Action, v.Scope, v.Target, v.Reason, v.CreatedAt.UnixMilli(), v.Status, v.ActorKey)
	return err
}
func (s *Store) Suggestions(ctx context.Context, status string) ([]Suggestion, error) {
	q := `SELECT id,actor_key,action,scope,target,reason,created_at,status,decision_id,resolved_at FROM suggestions`
	args := []any{}
	if status != "" {
		q += ` WHERE status=?`
		args = append(args, status)
	}
	q += ` ORDER BY created_at DESC LIMIT 500`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Suggestion{}
	for rows.Next() {
		var v Suggestion
		var created int64
		var resolved sql.NullInt64
		if err := rows.Scan(&v.ID, &v.ActorKey, &v.Action, &v.Scope, &v.Target, &v.Reason, &created, &v.Status, &v.DecisionID, &resolved); err != nil {
			return nil, err
		}
		v.CreatedAt = time.UnixMilli(created).UTC()
		if resolved.Valid {
			t := time.UnixMilli(resolved.Int64).UTC()
			v.ResolvedAt = &t
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Store) ResolveSuggestion(ctx context.Context, id, status, decisionID string) (Suggestion, error) {
	var v Suggestion
	if status == "revoked" && decisionID == "" {
		_ = s.db.QueryRowContext(ctx, `SELECT decision_id FROM suggestions WHERE id=?`, id).Scan(&decisionID)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return v, err
	}
	defer tx.Rollback()
	now := time.Now().UnixMilli()
	res, err := tx.ExecContext(ctx, `UPDATE suggestions SET status=?,decision_id=?,resolved_at=? WHERE id=? AND (status='pending' OR status='approved')`, status, decisionID, now, id)
	if err != nil {
		return v, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return v, sql.ErrNoRows
	}
	var created, resolved int64
	err = tx.QueryRowContext(ctx, `SELECT id,actor_key,action,scope,target,reason,created_at,status,decision_id,resolved_at FROM suggestions WHERE id=?`, id).Scan(&v.ID, &v.ActorKey, &v.Action, &v.Scope, &v.Target, &v.Reason, &created, &v.Status, &v.DecisionID, &resolved)
	if err != nil {
		return v, err
	}
	v.CreatedAt = time.UnixMilli(created).UTC()
	t := time.UnixMilli(resolved).UTC()
	v.ResolvedAt = &t
	return v, tx.Commit()
}
