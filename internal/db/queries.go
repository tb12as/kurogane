package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// ---- audit (append-only; triggers enforce it) ----

func (s *SQLite) AppendAudit(ctx context.Context, e AuditEntry) error {
	if e.TS.IsZero() {
		e.TS = time.Now()
	}
	if e.ServerID == "" {
		e.ServerID = "local"
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO audit(actor,action,target,before,after,ts,source_ip,server_id)
		VALUES(?,?,?,?,?,?,?,?)`, e.Actor, e.Action, e.Target, e.Before, e.After, e.TS.Unix(), e.SourceIP, e.ServerID)
	return err
}

func (s *SQLite) ListAudit(ctx context.Context, f AuditFilter) ([]AuditEntry, error) {
	q := `SELECT id,actor,action,target,before,after,ts,source_ip,server_id FROM audit WHERE ts >= ?`
	args := []any{unix(f.Since)}
	if f.Actor != "" {
		q += " AND actor = ?"
		args = append(args, f.Actor)
	}
	if f.Action != "" {
		q += " AND action LIKE ?"
		args = append(args, f.Action+"%")
	}
	if f.Limit <= 0 {
		f.Limit = 200
	}
	q += " ORDER BY id DESC LIMIT ? OFFSET ?"
	args = append(args, f.Limit, f.Offset)
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts int64
		if err := rows.Scan(&e.ID, &e.Actor, &e.Action, &e.Target, &e.Before, &e.After, &ts, &e.SourceIP, &e.ServerID); err != nil {
			return nil, err
		}
		e.TS = fromUnix(ts)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *SQLite) PruneAudit(ctx context.Context, before time.Time) (int64, error) {
	r, err := s.w.ExecContext(ctx, "DELETE FROM audit WHERE ts < ?", before.Unix())
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}

// ---- servers ----

const serverCols = "id,name,tags,os,kernel,agent_version,last_seen,cert_fingerprint,enrolled_at,status,score,grade"

func scanServer(sc interface{ Scan(...any) error }) (Server, error) {
	var x Server
	var tags string
	var ls, ea int64
	err := sc.Scan(&x.ID, &x.Name, &tags, &x.OS, &x.Kernel, &x.AgentVersion, &ls, &x.CertFingerprint, &ea, &x.Status,
		&x.Score, &x.Grade)
	unjs(tags, &x.Tags)
	x.LastSeen, x.EnrolledAt = fromUnix(ls), fromUnix(ea)
	return x, one(err)
}

func (s *SQLite) UpsertServer(ctx context.Context, x Server) error {
	_, err := s.w.ExecContext(ctx, `INSERT INTO servers(`+serverCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name,tags=excluded.tags,os=excluded.os,kernel=excluded.kernel,
		agent_version=excluded.agent_version,last_seen=excluded.last_seen,cert_fingerprint=excluded.cert_fingerprint,
		enrolled_at=excluded.enrolled_at,status=excluded.status,score=excluded.score,grade=excluded.grade`,
		x.ID, x.Name, js(nonNil(x.Tags)), x.OS, x.Kernel, x.AgentVersion, unix(x.LastSeen), x.CertFingerprint,
		unix(x.EnrolledAt), x.Status, x.Score, x.Grade)
	return err
}

func (s *SQLite) GetServer(ctx context.Context, id string) (Server, error) {
	return scanServer(s.r.QueryRowContext(ctx, "SELECT "+serverCols+" FROM servers WHERE id=?", id))
}

func (s *SQLite) GetServerByName(ctx context.Context, name string) (Server, error) {
	return scanServer(s.r.QueryRowContext(ctx, "SELECT "+serverCols+" FROM servers WHERE name=?", name))
}

func (s *SQLite) ListServers(ctx context.Context) ([]Server, error) {
	rows, err := s.r.QueryContext(ctx, "SELECT "+serverCols+" FROM servers ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Server
	for rows.Next() {
		x, err := scanServer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (s *SQLite) TouchServer(ctx context.Context, id string, at time.Time, status string) error {
	_, err := s.w.ExecContext(ctx, "UPDATE servers SET last_seen=?, status=? WHERE id=?", unix(at), status, id)
	return err
}

func (s *SQLite) DeleteServer(ctx context.Context, id string) error {
	if _, err := s.w.ExecContext(ctx, "DELETE FROM fleet_sites WHERE server_id=?", id); err != nil {
		return err
	}
	_, err := s.w.ExecContext(ctx, "DELETE FROM servers WHERE id=?", id)
	return err
}

// ---- ssh keys ----

const keyCols = "server_id,fingerprint,user,type,bits,label,comment,options,public_key,owner_person,added_at,expires_at,last_used_at"

func scanKey(sc interface{ Scan(...any) error }) (SSHKey, error) {
	var k SSHKey
	var a, e, l int64
	err := sc.Scan(&k.ServerID, &k.Fingerprint, &k.User, &k.Type, &k.Bits, &k.Label, &k.Comment, &k.Options,
		&k.PublicKey, &k.OwnerPerson, &a, &e, &l)
	k.AddedAt, k.ExpiresAt, k.LastUsedAt = fromUnix(a), fromUnix(e), fromUnix(l)
	return k, one(err)
}

func (s *SQLite) UpsertKey(ctx context.Context, k SSHKey) error {
	if k.ServerID == "" {
		k.ServerID = "local"
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO ssh_keys(`+keyCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(server_id,user,fingerprint) DO UPDATE SET type=excluded.type,bits=excluded.bits,label=excluded.label,
		comment=excluded.comment,options=excluded.options,public_key=excluded.public_key,owner_person=excluded.owner_person,
		added_at=excluded.added_at,expires_at=excluded.expires_at,last_used_at=excluded.last_used_at`,
		k.ServerID, k.Fingerprint, k.User, k.Type, k.Bits, k.Label, k.Comment, k.Options, k.PublicKey, k.OwnerPerson,
		unix(k.AddedAt), unix(k.ExpiresAt), unix(k.LastUsedAt))
	return err
}

func (s *SQLite) queryKeys(ctx context.Context, q string, args ...any) ([]SSHKey, error) {
	rows, err := s.r.QueryContext(ctx, "SELECT "+keyCols+" FROM ssh_keys "+q, args...) // #nosec G202 -- only constant column lists are concatenated; values are bound
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SSHKey
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *SQLite) ListKeys(ctx context.Context, serverID, user string) ([]SSHKey, error) {
	q, args := "WHERE 1=1", []any{}
	if serverID != "" {
		q += " AND server_id=?"
		args = append(args, serverID)
	}
	if user != "" {
		q += " AND user=?"
		args = append(args, user)
	}
	return s.queryKeys(ctx, q+" ORDER BY user, fingerprint", args...)
}

func (s *SQLite) FindKeys(ctx context.Context, fp string) ([]SSHKey, error) {
	return s.queryKeys(ctx, "WHERE fingerprint=?", fp)
}

func (s *SQLite) DeleteKey(ctx context.Context, serverID, user, fp string) error {
	_, err := s.w.ExecContext(ctx, "DELETE FROM ssh_keys WHERE server_id=? AND user=? AND fingerprint=?", serverID, user, fp)
	return err
}

// ---- people & groups (fleet, SSH-7) ----

func (s *SQLite) CreatePerson(ctx context.Context, p Person) error {
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now()
	}
	_, err := s.w.ExecContext(ctx, "INSERT INTO people(id,name,email,created_at) VALUES(?,?,?,?)",
		p.ID, p.Name, p.Email, p.CreatedAt.Unix())
	return err
}

func (s *SQLite) fillPerson(ctx context.Context, p *Person) error {
	rows, err := s.r.QueryContext(ctx, "SELECT fingerprint,public_key,login_user FROM person_keys WHERE person_id=?", p.ID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var k PersonKey
		if err := rows.Scan(&k.Fingerprint, &k.PublicKey, &k.LoginUser); err != nil {
			rows.Close()
			return err
		}
		p.Keys = append(p.Keys, k)
	}
	rows.Close()
	rows, err = s.r.QueryContext(ctx, "SELECT group_name FROM person_groups WHERE person_id=? ORDER BY group_name", p.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			return err
		}
		p.Groups = append(p.Groups, g)
	}
	return rows.Err()
}

func (s *SQLite) GetPerson(ctx context.Context, idOrName string) (Person, error) {
	var p Person
	var c int64
	err := s.r.QueryRowContext(ctx, "SELECT id,name,email,created_at FROM people WHERE id=? OR name=?", idOrName, idOrName).
		Scan(&p.ID, &p.Name, &p.Email, &c)
	if err != nil {
		return p, one(err)
	}
	p.CreatedAt = fromUnix(c)
	return p, s.fillPerson(ctx, &p)
}

func (s *SQLite) ListPeople(ctx context.Context) ([]Person, error) {
	rows, err := s.r.QueryContext(ctx, "SELECT id,name,email,created_at FROM people ORDER BY name")
	if err != nil {
		return nil, err
	}
	var out []Person
	for rows.Next() {
		var p Person
		var c int64
		if err := rows.Scan(&p.ID, &p.Name, &p.Email, &c); err != nil {
			rows.Close()
			return nil, err
		}
		p.CreatedAt = fromUnix(c)
		out = append(out, p)
	}
	rows.Close()
	for i := range out {
		if err := s.fillPerson(ctx, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *SQLite) DeletePerson(ctx context.Context, id string) error {
	_, err := s.w.ExecContext(ctx, "DELETE FROM people WHERE id=?", id)
	return err
}

func (s *SQLite) AddPersonKey(ctx context.Context, pid string, k PersonKey) error {
	_, err := s.w.ExecContext(ctx, `INSERT INTO person_keys(person_id,fingerprint,public_key,login_user) VALUES(?,?,?,?)
		ON CONFLICT DO UPDATE SET public_key=excluded.public_key, login_user=excluded.login_user`,
		pid, k.Fingerprint, k.PublicKey, k.LoginUser)
	return err
}

func (s *SQLite) RemovePersonKey(ctx context.Context, pid, fp string) error {
	_, err := s.w.ExecContext(ctx, "DELETE FROM person_keys WHERE person_id=? AND fingerprint=?", pid, fp)
	return err
}

func (s *SQLite) SetPersonGroup(ctx context.Context, pid, group string, member bool) error {
	q := "DELETE FROM person_groups WHERE person_id=? AND group_name=?"
	if member {
		q = "INSERT OR IGNORE INTO person_groups(person_id,group_name) VALUES(?,?)"
	}
	_, err := s.w.ExecContext(ctx, q, pid, group)
	return err
}

func (s *SQLite) GroupMembers(ctx context.Context, group string) ([]Person, error) {
	rows, err := s.r.QueryContext(ctx, "SELECT person_id FROM person_groups WHERE group_name=?", group)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	var out []Person
	for _, id := range ids {
		p, err := s.GetPerson(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func (s *SQLite) ListGroups(ctx context.Context) (map[string][]string, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT g.group_name, p.name FROM person_groups g JOIN people p ON p.id=g.person_id
		ORDER BY g.group_name, p.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var g, n string
		if err := rows.Scan(&g, &n); err != nil {
			return nil, err
		}
		out[g] = append(out[g], n)
	}
	return out, rows.Err()
}

// ---- ssh changes ----

func (s *SQLite) SaveSSHChange(ctx context.Context, c SSHChange) error {
	if c.ServerID == "" {
		c.ServerID = "local"
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO ssh_changes(id,server_id,actor,setting,old_value,new_value,status,ts,deadline,backup_path)
		VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status`,
		c.ID, c.ServerID, c.Actor, c.Setting, c.OldValue, c.NewValue, c.Status, unix(c.TS), unix(c.Deadline), c.BackupPath)
	return err
}

func (s *SQLite) ListSSHChanges(ctx context.Context, limit int) ([]SSHChange, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.r.QueryContext(ctx, `SELECT id,server_id,actor,setting,old_value,new_value,status,ts,deadline,backup_path
		FROM ssh_changes ORDER BY ts DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SSHChange
	for rows.Next() {
		var c SSHChange
		var ts, dl int64
		if err := rows.Scan(&c.ID, &c.ServerID, &c.Actor, &c.Setting, &c.OldValue, &c.NewValue, &c.Status, &ts, &dl, &c.BackupPath); err != nil {
			return nil, err
		}
		c.TS, c.Deadline = fromUnix(ts), fromUnix(dl)
		out = append(out, c)
	}
	return out, rows.Err()
}

// ---- site changes ----

func (s *SQLite) SaveSiteChange(ctx context.Context, c SiteChange) error {
	if c.ServerID == "" {
		c.ServerID = "local"
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO site_changes(id,server_id,actor,site_id,site_name,kind,action,ops,status,error,ts)
		VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status, error=excluded.error`,
		c.ID, c.ServerID, c.Actor, c.SiteID, c.SiteName, c.Kind, c.Action, c.Ops, c.Status, c.Error, unix(c.TS))
	return err
}

func (s *SQLite) ListSiteChanges(ctx context.Context, limit int) ([]SiteChange, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.r.QueryContext(ctx, `SELECT id,server_id,actor,site_id,site_name,kind,action,ops,status,error,ts
		FROM site_changes ORDER BY ts DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SiteChange{}
	for rows.Next() {
		var c SiteChange
		var ts int64
		if err := rows.Scan(&c.ID, &c.ServerID, &c.Actor, &c.SiteID, &c.SiteName, &c.Kind, &c.Action, &c.Ops, &c.Status,
			&c.Error, &ts); err != nil {
			return nil, err
		}
		c.TS = fromUnix(ts)
		out = append(out, c)
	}
	return out, rows.Err()
}

// ---- fleet sites (central) ----

func (s *SQLite) SaveFleetSites(ctx context.Context, f FleetSites) error {
	_, err := s.w.ExecContext(ctx, `INSERT INTO fleet_sites(server_id,data,updated_at) VALUES(?,?,?)
		ON CONFLICT(server_id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at`,
		f.ServerID, string(f.Data), unix(f.UpdatedAt))
	return err
}

func (s *SQLite) ListFleetSites(ctx context.Context) ([]FleetSites, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT server_id,data,updated_at FROM fleet_sites ORDER BY server_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FleetSites{}
	for rows.Next() {
		var f FleetSites
		var data string
		var ts int64
		if err := rows.Scan(&f.ServerID, &data, &ts); err != nil {
			return nil, err
		}
		f.Data, f.UpdatedAt = json.RawMessage(data), fromUnix(ts)
		out = append(out, f)
	}
	return out, rows.Err()
}

// ---- scans & fixes & ignores ----

func (s *SQLite) SaveScan(ctx context.Context, x Scan) error {
	if x.ServerID == "" {
		x.ServerID = "local"
	}
	if len(x.Results) == 0 {
		x.Results = json.RawMessage("[]")
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO scans(id,server_id,started_at,finished_at,score,grade,results) VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET finished_at=excluded.finished_at,score=excluded.score,grade=excluded.grade,results=excluded.results`,
		x.ID, x.ServerID, unix(x.StartedAt), unix(x.FinishedAt), x.Score, x.Grade, string(x.Results))
	return err
}

func scanScan(sc interface{ Scan(...any) error }) (Scan, error) {
	var x Scan
	var a, b int64
	var res string
	err := sc.Scan(&x.ID, &x.ServerID, &a, &b, &x.Score, &x.Grade, &res)
	x.StartedAt, x.FinishedAt, x.Results = fromUnix(a), fromUnix(b), json.RawMessage(res)
	return x, one(err)
}

func (s *SQLite) GetScan(ctx context.Context, id string) (Scan, error) {
	if id == "latest" {
		return scanScan(s.r.QueryRowContext(ctx, `SELECT id,server_id,started_at,finished_at,score,grade,results FROM scans
			WHERE server_id='local' ORDER BY started_at DESC LIMIT 1`))
	}
	return scanScan(s.r.QueryRowContext(ctx, `SELECT id,server_id,started_at,finished_at,score,grade,results FROM scans WHERE id=?`, id))
}

func (s *SQLite) ListScans(ctx context.Context, serverID string, limit int) ([]Scan, error) {
	if limit <= 0 {
		limit = 50
	}
	q, args := `SELECT id,server_id,started_at,finished_at,score,grade,'[]' FROM scans`, []any{}
	if serverID != "" {
		q += " WHERE server_id=?"
		args = append(args, serverID)
	}
	rows, err := s.r.QueryContext(ctx, q+" ORDER BY started_at DESC LIMIT ?", append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Scan
	for rows.Next() {
		x, err := scanScan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (s *SQLite) SaveFix(ctx context.Context, f Fix) error {
	if f.ServerID == "" {
		f.ServerID = "local"
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO fixes(id,server_id,check_id,diff,backup_path,applied_by,applied_at,reverted_at,status)
		VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET reverted_at=excluded.reverted_at,status=excluded.status`,
		f.ID, f.ServerID, f.CheckID, f.Diff, f.BackupPath, f.AppliedBy, unix(f.AppliedAt), unix(f.RevertedAt), f.Status)
	return err
}

func scanFix(sc interface{ Scan(...any) error }) (Fix, error) {
	var f Fix
	var a, r int64
	err := sc.Scan(&f.ID, &f.ServerID, &f.CheckID, &f.Diff, &f.BackupPath, &f.AppliedBy, &a, &r, &f.Status)
	f.AppliedAt, f.RevertedAt = fromUnix(a), fromUnix(r)
	return f, one(err)
}

const fixCols = "id,server_id,check_id,diff,backup_path,applied_by,applied_at,reverted_at,status"

func (s *SQLite) GetFix(ctx context.Context, id string) (Fix, error) {
	return scanFix(s.r.QueryRowContext(ctx, "SELECT "+fixCols+" FROM fixes WHERE id=?", id))
}

func (s *SQLite) ListFixes(ctx context.Context, serverID string, limit int) ([]Fix, error) {
	if limit <= 0 {
		limit = 100
	}
	q, args := "SELECT "+fixCols+" FROM fixes", []any{}
	if serverID != "" {
		q += " WHERE server_id=?"
		args = append(args, serverID)
	}
	rows, err := s.r.QueryContext(ctx, q+" ORDER BY applied_at DESC LIMIT ?", append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Fix
	for rows.Next() {
		f, err := scanFix(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *SQLite) SetIgnore(ctx context.Context, ig Ignore) error {
	if strings.TrimSpace(ig.Reason) == "" {
		return errors.New("ignore reason is mandatory (HD-6)")
	}
	if ig.ServerID == "" {
		ig.ServerID = "local"
	}
	if ig.CreatedAt.IsZero() {
		ig.CreatedAt = time.Now()
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO harden_ignores(server_id,check_id,reason,created_by,created_at) VALUES(?,?,?,?,?)
		ON CONFLICT DO UPDATE SET reason=excluded.reason,created_by=excluded.created_by,created_at=excluded.created_at`,
		ig.ServerID, ig.CheckID, ig.Reason, ig.CreatedBy, ig.CreatedAt.Unix())
	return err
}

func (s *SQLite) DeleteIgnore(ctx context.Context, serverID, checkID string) error {
	_, err := s.w.ExecContext(ctx, "DELETE FROM harden_ignores WHERE server_id=? AND check_id=?", serverID, checkID)
	return err
}

func (s *SQLite) ListIgnores(ctx context.Context, serverID string) ([]Ignore, error) {
	rows, err := s.r.QueryContext(ctx, "SELECT server_id,check_id,reason,created_by,created_at FROM harden_ignores WHERE server_id=?", serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Ignore
	for rows.Next() {
		var ig Ignore
		var c int64
		if err := rows.Scan(&ig.ServerID, &ig.CheckID, &ig.Reason, &ig.CreatedBy, &c); err != nil {
			return nil, err
		}
		ig.CreatedAt = fromUnix(c)
		out = append(out, ig)
	}
	return out, rows.Err()
}

// ---- alert rules / events / silences / channels ----

func (s *SQLite) UpsertRule(ctx context.Context, r AlertRule) error {
	_, err := s.w.ExecContext(ctx, `INSERT INTO alert_rules(id,name,expr,for_s,severity,channels,enabled,tags,builtin)
		VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,expr=excluded.expr,for_s=excluded.for_s,
		severity=excluded.severity,channels=excluded.channels,enabled=excluded.enabled,tags=excluded.tags,builtin=excluded.builtin`,
		r.ID, r.Name, r.Expr, int64(r.For/time.Second), r.Severity, js(nonNil(r.Channels)), r.Enabled, js(nonNil(r.Tags)), r.Builtin)
	return err
}

func scanRule(sc interface{ Scan(...any) error }) (AlertRule, error) {
	var r AlertRule
	var f int64
	var ch, tags string
	err := sc.Scan(&r.ID, &r.Name, &r.Expr, &f, &r.Severity, &ch, &r.Enabled, &tags, &r.Builtin)
	r.For = time.Duration(f) * time.Second
	unjs(ch, &r.Channels)
	unjs(tags, &r.Tags)
	return r, one(err)
}

const ruleCols = "id,name,expr,for_s,severity,channels,enabled,tags,builtin"

func (s *SQLite) GetRule(ctx context.Context, id string) (AlertRule, error) {
	return scanRule(s.r.QueryRowContext(ctx, "SELECT "+ruleCols+" FROM alert_rules WHERE id=?", id))
}

func (s *SQLite) ListRules(ctx context.Context) ([]AlertRule, error) {
	rows, err := s.r.QueryContext(ctx, "SELECT "+ruleCols+" FROM alert_rules ORDER BY builtin DESC, id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertRule
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLite) DeleteRule(ctx context.Context, id string) error {
	_, err := s.w.ExecContext(ctx, "DELETE FROM alert_rules WHERE id=?", id)
	return err
}

const eventCols = "id,rule_id,server_id,fingerprint,state,severity,summary,started_at,acked_at,acked_by,resolved_at,last_sent_at,noise,payload"

func scanEvent(sc interface{ Scan(...any) error }) (AlertEvent, error) {
	var e AlertEvent
	var st, ack, res, sent int64
	var p string
	err := sc.Scan(&e.ID, &e.RuleID, &e.ServerID, &e.Fingerprint, &e.State, &e.Severity, &e.Summary, &st, &ack, &e.AckedBy,
		&res, &sent, &e.Noise, &p)
	e.StartedAt, e.AckedAt, e.ResolvedAt, e.LastSentAt = fromUnix(st), fromUnix(ack), fromUnix(res), fromUnix(sent)
	e.Payload = json.RawMessage(p)
	return e, one(err)
}

func (s *SQLite) SaveEvent(ctx context.Context, e AlertEvent) error {
	if e.ServerID == "" {
		e.ServerID = "local"
	}
	if len(e.Payload) == 0 {
		e.Payload = json.RawMessage("{}")
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO alert_events(`+eventCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET state=excluded.state,severity=excluded.severity,summary=excluded.summary,
		acked_at=excluded.acked_at,acked_by=excluded.acked_by,resolved_at=excluded.resolved_at,
		last_sent_at=excluded.last_sent_at,noise=excluded.noise,payload=excluded.payload`,
		e.ID, e.RuleID, e.ServerID, e.Fingerprint, e.State, e.Severity, e.Summary, unix(e.StartedAt), unix(e.AckedAt),
		e.AckedBy, unix(e.ResolvedAt), unix(e.LastSentAt), e.Noise, string(e.Payload))
	return err
}

func (s *SQLite) GetEvent(ctx context.Context, id string) (AlertEvent, error) {
	return scanEvent(s.r.QueryRowContext(ctx, "SELECT "+eventCols+" FROM alert_events WHERE id=?", id))
}

// OpenEvent returns the non-resolved event for a fingerprint (dedup key).
func (s *SQLite) OpenEvent(ctx context.Context, fp string) (AlertEvent, error) {
	return scanEvent(s.w.QueryRowContext(ctx, "SELECT "+eventCols+
		" FROM alert_events WHERE fingerprint=? AND state!='resolved' ORDER BY started_at DESC LIMIT 1", fp))
}

func (s *SQLite) ListEvents(ctx context.Context, f EventFilter) ([]AlertEvent, error) {
	q, args := "SELECT "+eventCols+" FROM alert_events WHERE started_at >= ?", []any{unix(f.Since)}
	if f.State == "open" {
		q += " AND state != 'resolved'"
	} else if f.State != "" {
		q += " AND state = ?"
		args = append(args, f.State)
	}
	if f.RuleID != "" {
		q += " AND rule_id = ?"
		args = append(args, f.RuleID)
	}
	if f.ServerID != "" {
		q += " AND server_id = ?"
		args = append(args, f.ServerID)
	}
	if f.Limit <= 0 {
		f.Limit = 200
	}
	rows, err := s.r.QueryContext(ctx, q+" ORDER BY started_at DESC LIMIT ?", append(args, f.Limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertEvent
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *SQLite) SaveSilence(ctx context.Context, x Silence) error {
	_, err := s.w.ExecContext(ctx, `INSERT INTO silences(id,matcher,starts_at,ends_at,created_by,reason) VALUES(?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET matcher=excluded.matcher,starts_at=excluded.starts_at,ends_at=excluded.ends_at,reason=excluded.reason`,
		x.ID, js(x.Matcher), unix(x.StartsAt), unix(x.EndsAt), x.CreatedBy, x.Reason)
	return err
}

func (s *SQLite) DeleteSilence(ctx context.Context, id string) error {
	_, err := s.w.ExecContext(ctx, "DELETE FROM silences WHERE id=?", id)
	return err
}

// ListSilences returns silences active at t, or all when t is zero.
func (s *SQLite) ListSilences(ctx context.Context, t time.Time) ([]Silence, error) {
	q, args := "SELECT id,matcher,starts_at,ends_at,created_by,reason FROM silences", []any{}
	if !t.IsZero() {
		q += " WHERE starts_at <= ? AND ends_at > ?"
		args = append(args, t.Unix(), t.Unix())
	}
	rows, err := s.r.QueryContext(ctx, q+" ORDER BY starts_at DESC", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Silence
	for rows.Next() {
		var x Silence
		var m string
		var a, b int64
		if err := rows.Scan(&x.ID, &m, &a, &b, &x.CreatedBy, &x.Reason); err != nil {
			return nil, err
		}
		unjs(m, &x.Matcher)
		x.StartsAt, x.EndsAt = fromUnix(a), fromUnix(b)
		out = append(out, x)
	}
	return out, rows.Err()
}

func (s *SQLite) UpsertChannel(ctx context.Context, c Channel) error {
	_, err := s.w.ExecContext(ctx, `INSERT INTO channels(name,type,config) VALUES(?,?,?)
		ON CONFLICT(name) DO UPDATE SET type=excluded.type, config=excluded.config`, c.Name, c.Type, js(c.Config))
	return err
}

func (s *SQLite) DeleteChannel(ctx context.Context, name string) error {
	_, err := s.w.ExecContext(ctx, "DELETE FROM channels WHERE name=?", name)
	return err
}

func (s *SQLite) ListChannels(ctx context.Context) ([]Channel, error) {
	rows, err := s.r.QueryContext(ctx, "SELECT name,type,config FROM channels ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Channel
	for rows.Next() {
		var c Channel
		var cfg string
		if err := rows.Scan(&c.Name, &c.Type, &cfg); err != nil {
			return nil, err
		}
		unjs(cfg, &c.Config)
		out = append(out, c)
	}
	return out, rows.Err()
}

// ---- users / sessions / tokens ----

const userCols = "id,username,password_hash,totp_secret,totp_enabled,role,failed_logins,locked_until,oidc_subject,created_at"

func scanUser(sc interface{ Scan(...any) error }) (User, error) {
	var u User
	var l, c int64
	err := sc.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.TOTPSecret, &u.TOTPEnabled, &u.Role, &u.FailedLogins, &l,
		&u.OIDCSubject, &c)
	u.LockedUntil, u.CreatedAt = fromUnix(l), fromUnix(c)
	return u, one(err)
}

func (s *SQLite) SaveUser(ctx context.Context, u User) error {
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now()
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO users(`+userCols+`) VALUES(?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET username=excluded.username,password_hash=excluded.password_hash,
		totp_secret=excluded.totp_secret,totp_enabled=excluded.totp_enabled,role=excluded.role,
		failed_logins=excluded.failed_logins,locked_until=excluded.locked_until,oidc_subject=excluded.oidc_subject`,
		u.ID, u.Username, u.PasswordHash, u.TOTPSecret, u.TOTPEnabled, u.Role, u.FailedLogins, unix(u.LockedUntil),
		u.OIDCSubject, unix(u.CreatedAt))
	return err
}

func (s *SQLite) GetUser(ctx context.Context, id string) (User, error) {
	return scanUser(s.r.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE id=?", id))
}

func (s *SQLite) GetUserByName(ctx context.Context, n string) (User, error) {
	return scanUser(s.w.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE username=?", n))
}

func (s *SQLite) GetUserByOIDC(ctx context.Context, sub string) (User, error) {
	if sub == "" {
		return User{}, ErrNotFound
	}
	return scanUser(s.r.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE oidc_subject=?", sub))
}

func (s *SQLite) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.r.QueryContext(ctx, "SELECT "+userCols+" FROM users ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *SQLite) DeleteUser(ctx context.Context, id string) error {
	_, err := s.w.ExecContext(ctx, "DELETE FROM users WHERE id=?", id)
	return err
}

func (s *SQLite) CreateSession(ctx context.Context, x Session) error {
	_, err := s.w.ExecContext(ctx, "INSERT INTO sessions(id,user_id,csrf,ip,created_at,expires_at) VALUES(?,?,?,?,?,?)",
		x.ID, x.UserID, x.CSRF, x.IP, unix(x.CreatedAt), unix(x.ExpiresAt))
	return err
}

func (s *SQLite) GetSession(ctx context.Context, id string) (Session, error) {
	var x Session
	var c, e int64
	err := s.r.QueryRowContext(ctx, "SELECT id,user_id,csrf,ip,created_at,expires_at FROM sessions WHERE id=?", id).
		Scan(&x.ID, &x.UserID, &x.CSRF, &x.IP, &c, &e)
	x.CreatedAt, x.ExpiresAt = fromUnix(c), fromUnix(e)
	return x, one(err)
}

func (s *SQLite) DeleteSession(ctx context.Context, id string) error {
	_, err := s.w.ExecContext(ctx, "DELETE FROM sessions WHERE id=?", id)
	return err
}

func (s *SQLite) PruneSessions(ctx context.Context, now time.Time) error {
	_, err := s.w.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at < ?", now.Unix())
	return err
}

func (s *SQLite) CreateToken(ctx context.Context, t APIToken) error {
	_, err := s.w.ExecContext(ctx, `INSERT INTO api_tokens(id,name,hash,scopes,created_by,created_at,expires_at,last_used_at)
		VALUES(?,?,?,?,?,?,?,0)`, t.ID, t.Name, t.Hash, js(t.Scopes), t.CreatedBy, unix(t.CreatedAt), unix(t.ExpiresAt))
	return err
}

func scanToken(sc interface{ Scan(...any) error }) (APIToken, error) {
	var t APIToken
	var sc2 string
	var c, e, l int64
	err := sc.Scan(&t.ID, &t.Name, &t.Hash, &sc2, &t.CreatedBy, &c, &e, &l)
	unjs(sc2, &t.Scopes)
	t.CreatedAt, t.ExpiresAt, t.LastUsedAt = fromUnix(c), fromUnix(e), fromUnix(l)
	return t, one(err)
}

const tokenCols = "id,name,hash,scopes,created_by,created_at,expires_at,last_used_at"

func (s *SQLite) GetTokenByHash(ctx context.Context, h string) (APIToken, error) {
	return scanToken(s.r.QueryRowContext(ctx, "SELECT "+tokenCols+" FROM api_tokens WHERE hash=?", h))
}

func (s *SQLite) ListTokens(ctx context.Context) ([]APIToken, error) {
	rows, err := s.r.QueryContext(ctx, "SELECT "+tokenCols+" FROM api_tokens ORDER BY created_at")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *SQLite) DeleteToken(ctx context.Context, id string) error {
	_, err := s.w.ExecContext(ctx, "DELETE FROM api_tokens WHERE id=? OR name=?", id, id)
	return err
}

func (s *SQLite) TouchToken(ctx context.Context, id string, at time.Time) error {
	_, err := s.w.ExecContext(ctx, "UPDATE api_tokens SET last_used_at=? WHERE id=?", at.Unix(), id)
	return err
}

// ---- enrollment ----

func (s *SQLite) CreateEnrollToken(ctx context.Context, t EnrollToken) error {
	_, err := s.w.ExecContext(ctx, `INSERT INTO enrollment_tokens(hash,server_name,created_by,created_at,expires_at) VALUES(?,?,?,?,?)`,
		t.Hash, t.ServerName, t.CreatedBy, unix(t.CreatedAt), unix(t.ExpiresAt))
	return err
}

// UseEnrollToken atomically marks a one-time token as used if it is unexpired and unused.
func (s *SQLite) UseEnrollToken(ctx context.Context, hash string, now time.Time) (EnrollToken, error) {
	r, err := s.w.ExecContext(ctx, `UPDATE enrollment_tokens SET used_at=? WHERE hash=? AND used_at=0 AND expires_at>?`,
		now.Unix(), hash, now.Unix())
	if err != nil {
		return EnrollToken{}, err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return EnrollToken{}, errors.New("enrollment token invalid, expired or already used: create a new one with `serverkeeper server token`")
	}
	var t EnrollToken
	var c, e, u int64
	err = s.w.QueryRowContext(ctx, "SELECT hash,server_name,created_by,created_at,expires_at,used_at FROM enrollment_tokens WHERE hash=?", hash).
		Scan(&t.Hash, &t.ServerName, &t.CreatedBy, &c, &e, &u)
	t.CreatedAt, t.ExpiresAt, t.UsedAt = fromUnix(c), fromUnix(e), fromUnix(u)
	return t, one(err)
}

// ---- fleet ops ----

func (s *SQLite) EnqueueOp(ctx context.Context, op FleetOp) error {
	if op.CreatedAt.IsZero() {
		op.CreatedAt = time.Now()
	}
	if op.Status == "" {
		op.Status = "pending"
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO fleet_ops(id,server_id,kind,payload,status,result,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)`,
		op.ID, op.ServerID, op.Kind, string(op.Payload), op.Status, op.Result, op.CreatedBy, op.CreatedAt.Unix())
	return err
}

func (s *SQLite) queryOps(ctx context.Context, q string, args ...any) ([]FleetOp, error) {
	rows, err := s.r.QueryContext(ctx, "SELECT id,server_id,kind,payload,status,result,created_by,created_at,done_at FROM fleet_ops "+q, args...) // #nosec G202 -- only constant column lists are concatenated; values are bound
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FleetOp
	for rows.Next() {
		var o FleetOp
		var p string
		var c, d int64
		if err := rows.Scan(&o.ID, &o.ServerID, &o.Kind, &p, &o.Status, &o.Result, &o.CreatedBy, &c, &d); err != nil {
			return nil, err
		}
		o.Payload, o.CreatedAt, o.DoneAt = json.RawMessage(p), fromUnix(c), fromUnix(d)
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *SQLite) PendingOps(ctx context.Context, serverID string) ([]FleetOp, error) {
	return s.queryOps(ctx, "WHERE server_id=? AND status IN ('pending','sent') ORDER BY created_at", serverID)
}

func (s *SQLite) ListOps(ctx context.Context, limit int) ([]FleetOp, error) {
	if limit <= 0 {
		limit = 200
	}
	return s.queryOps(ctx, "ORDER BY created_at DESC LIMIT ?", limit)
}

func (s *SQLite) UpdateOp(ctx context.Context, id, status, result string) error {
	done := int64(0)
	if status == "done" || status == "failed" {
		done = time.Now().Unix()
	}
	_, err := s.w.ExecContext(ctx, "UPDATE fleet_ops SET status=?, result=?, done_at=? WHERE id=?", status, result, done, id)
	return err
}

// ---- kv ----

func (s *SQLite) GetKV(ctx context.Context, key string) (string, error) {
	var v string
	err := s.r.QueryRowContext(ctx, "SELECT value FROM kv WHERE key=?", key).Scan(&v)
	return v, one(err)
}

func (s *SQLite) SetKV(ctx context.Context, key, value string) error {
	_, err := s.w.ExecContext(ctx, "INSERT INTO kv(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, value)
	return err
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

var _ = sql.ErrNoRows
