package history

import (
	"context"
	"time"
)

type Egress struct {
	TS      time.Time `json:"ts"`
	Comm    string    `json:"comm"`
	PID     uint32    `json:"pid"`
	UID     uint32    `json:"uid"`
	DstIP   string    `json:"dst_ip"`
	DstPort uint16    `json:"dst_port"`
	Count   int       `json:"count"`
}

func (s *Store) RecordEgress(ctx context.Context, e Egress) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO egress(ts,comm,pid,uid,dst_ip,dst_port,count)VALUES(?,?,?,?,?,?,?)`, e.TS.UnixMilli(), e.Comm, e.PID, e.UID, e.DstIP, e.DstPort, e.Count)
	return err
}
func (s *Store) Egress(ctx context.Context, since time.Time, limit int) ([]Egress, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	rows, err := s.db.QueryContext(ctx, `SELECT ts,comm,pid,uid,dst_ip,dst_port,count FROM egress WHERE ts>=? ORDER BY ts DESC LIMIT ?`, since.UnixMilli(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Egress{}
	for rows.Next() {
		var e Egress
		var ts int64
		if err := rows.Scan(&ts, &e.Comm, &e.PID, &e.UID, &e.DstIP, &e.DstPort, &e.Count); err != nil {
			return nil, err
		}
		e.TS = time.UnixMilli(ts).UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}
func (s *Store) Prune(ctx context.Context, before time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{`DELETE FROM flows WHERE ts<?`, `DELETE FROM actors WHERE last_seen<?`, `DELETE FROM egress WHERE ts<?`} {
		if _, err = tx.ExecContext(ctx, q, before.UnixMilli()); err != nil {
			return err
		}
	}
	return tx.Commit()
}
