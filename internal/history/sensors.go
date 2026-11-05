package history

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Sensor is one registered edge sensor in the fleet registry (ADR 0004).
// Only the SHA-256 hash of the sensor key is stored; the plaintext key is
// returned once at creation time.
type Sensor struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	CreatedAt   time.Time  `json:"created_at"`
	LastSeenAt  *time.Time `json:"last_seen_at,omitempty"`
	EgressSince *time.Time `json:"egress_since,omitempty"`
	Dropped     int64      `json:"dropped"`
}

// CreateSensor registers a new sensor with the given display name and SHA-256
// key hash.
func (s *Store) CreateSensor(ctx context.Context, name, keyHash string) (Sensor, error) {
	if s == nil {
		return Sensor{}, fmt.Errorf("history: nil store")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return Sensor{}, fmt.Errorf("history: sensor name is required")
	}
	if len(name) > 80 {
		name = name[:80]
	}
	if keyHash == "" {
		return Sensor{}, fmt.Errorf("history: sensor key hash is required")
	}
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `INSERT INTO sensors(name, key_hash, created_at, dropped) VALUES(?, ?, ?, 0)`,
		name, keyHash, now.UnixMilli())
	if err != nil {
		return Sensor{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Sensor{}, err
	}
	return Sensor{
		ID:        id,
		Name:      name,
		CreatedAt: now.Truncate(time.Millisecond),
		Dropped:   0,
	}, nil
}

// Sensors returns all registered sensors ordered by ID ascending.
func (s *Store) Sensors(ctx context.Context) ([]Sensor, error) {
	if s == nil {
		return []Sensor{}, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, created_at, last_seen_at, egress_since, dropped FROM sensors ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Sensor{}
	for rows.Next() {
		sn, err := scanSensor(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sn)
	}
	return out, rows.Err()
}

// LookupSensorByHash looks up a sensor by its SHA-256 key hash.
func (s *Store) LookupSensorByHash(ctx context.Context, keyHash string) (Sensor, error) {
	if s == nil || keyHash == "" {
		return Sensor{}, sql.ErrNoRows
	}
	row := s.db.QueryRowContext(ctx, `SELECT id, name, created_at, last_seen_at, egress_since, dropped FROM sensors WHERE key_hash=?`, keyHash)
	return scanSensor(row)
}

// TouchSensor records a sensor check-in, accumulating dropped events and
// marking egress_since on the first batch carrying outbound records.
func (s *Store) TouchSensor(ctx context.Context, id int64, seenAt time.Time, droppedDelta int64, hasEgress bool) error {
	if s == nil {
		return nil
	}
	if seenAt.IsZero() {
		seenAt = time.Now().UTC()
	}
	if droppedDelta < 0 {
		droppedDelta = 0
	}
	seenMS := seenAt.UnixMilli()
	var err error
	if hasEgress {
		_, err = s.db.ExecContext(ctx, `UPDATE sensors SET last_seen_at=?, dropped=dropped+?, egress_since=COALESCE(egress_since, ?) WHERE id=?`,
			seenMS, droppedDelta, seenMS, id)
	} else {
		_, err = s.db.ExecContext(ctx, `UPDATE sensors SET last_seen_at=?, dropped=dropped+? WHERE id=?`,
			seenMS, droppedDelta, id)
	}
	return err
}

// DeleteSensor revokes a sensor's key and removes its flows, egress records,
// and any actors that have no remaining flows.
func (s *Store) DeleteSensor(ctx context.Context, id int64) error {
	if s == nil {
		return sql.ErrNoRows
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM sensors WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM flows WHERE sensor_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM egress WHERE sensor_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM actors WHERE NOT EXISTS (SELECT 1 FROM flows WHERE flows.actor_key = actors.key)`); err != nil {
		return err
	}
	return tx.Commit()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanSensor(r rowScanner) (Sensor, error) {
	var sn Sensor
	var created int64
	var lastSeen, egressSince sql.NullInt64
	if err := r.Scan(&sn.ID, &sn.Name, &created, &lastSeen, &egressSince, &sn.Dropped); err != nil {
		return Sensor{}, err
	}
	sn.CreatedAt = time.UnixMilli(created).UTC()
	if lastSeen.Valid {
		t := time.UnixMilli(lastSeen.Int64).UTC()
		sn.LastSeenAt = &t
	}
	if egressSince.Valid {
		t := time.UnixMilli(egressSince.Int64).UTC()
		sn.EgressSince = &t
	}
	return sn, nil
}
