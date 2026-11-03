// Package db is the SQLite metadata store (PRD §9 storage design): one writer connection, WAL,
// embedded goose migrations. All access goes through Store so another backend can be added later.
package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// SQLite implements Store.
type SQLite struct {
	w    *sql.DB // single writer
	r    *sql.DB // readers
	path string
}

const pragmas = "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)"

// Open opens the database, creates it with mode 0600 and runs migrations.
func Open(path string) (*SQLite, error) {
	if path != ":memory:" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", path, err)
		}
		f.Close()
		_ = os.Chmod(path, 0o600)
	}
	dsn := "file:" + path + pragmas
	w, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	r := w
	if path != ":memory:" {
		if r, err = sql.Open("sqlite", dsn+"&mode=ro"); err != nil {
			return nil, err
		}
		r.SetMaxOpenConns(4)
	}
	goose.SetBaseFS(migrations)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("sqlite3"); err != nil {
		return nil, err
	}
	if err := goose.Up(w, "migrations"); err != nil {
		return nil, fmt.Errorf("migrate %s: %w", path, err)
	}
	return &SQLite{w: w, r: r, path: path}, nil
}

// MigrateDown rolls back one migration (downgrade one minor version, §11.4).
// The initial schema is never rolled back since that would drop all data.
func (s *SQLite) MigrateDown() error {
	v, err := goose.GetDBVersion(s.w)
	if err != nil {
		return err
	}
	if v <= 1 {
		return fmt.Errorf("schema is at version %d: nothing to roll back (the initial schema is never dropped)", v)
	}
	return goose.Down(s.w, "migrations")
}

func (s *SQLite) Close() error {
	if s.r != s.w {
		s.r.Close()
	}
	return s.w.Close()
}

// VacuumInto writes a consistent copy of the database (backup).
func (s *SQLite) VacuumInto(ctx context.Context, dest string) error {
	_, err := s.w.ExecContext(ctx, "VACUUM INTO ?", dest)
	return err
}

// Path returns the database file path.
func (s *SQLite) Path() string { return s.path }

// NewID returns a random 16-hex-char id.
func NewID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func unix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func fromUnix(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(n, 0)
}

func js(v any) string {
	if v == nil {
		return "null"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func unjs(s string, v any) { _ = json.Unmarshal([]byte(s), v) }

func one(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
