package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/serverkeeper/serverkeeper/internal/auth"
	"github.com/serverkeeper/serverkeeper/internal/db"
	"github.com/serverkeeper/serverkeeper/internal/harden"
	"github.com/serverkeeper/serverkeeper/internal/harden/checks"
)

func init() { Register((*Server).hardenRoutes) }

type fixReq struct {
	CheckID  string `json:"check_id"`
	All      bool   `json:"all"`
	Severity string `json:"severity"`
	DryRun   bool   `json:"dry_run"`
	Confirm  bool   `json:"confirm"`
}

// hardenErr maps service errors to HTTP codes; messages already state the next step.
func hardenErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, harden.ErrUnknownCheck), errors.Is(err, db.ErrNotFound):
		return Errf(http.StatusNotFound, "%s", err.Error())
	case errors.Is(err, checks.ErrNoFix):
		return Errf(http.StatusBadRequest, "%s", err.Error())
	}
	return err
}

func hardenLimit(r *http.Request) int {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	return n
}

func (s *Server) hardenRoutes() {
	if s.Harden == nil {
		return
	}
	h := s.Harden
	s.Route("POST /harden/scans", auth.ScopeHarden, func(r *http.Request) (any, error) { return h.Scan(r.Context()) })
	s.Route("GET /harden/scans", auth.ScopeRead, func(r *http.Request) (any, error) {
		return h.ListScans(r.Context(), hardenLimit(r))
	})
	s.Route("GET /harden/scans/{id}", auth.ScopeRead, func(r *http.Request) (any, error) {
		sc, err := h.GetScan(r.Context(), r.PathValue("id"))
		return sc, hardenErr(err)
	})
	s.Raw("GET /api/v1/harden/scans/{id}/report", auth.ScopeRead, func(w http.ResponseWriter, r *http.Request) {
		sc, err := h.GetScan(r.Context(), r.PathValue("id"))
		if err != nil {
			writeErr(w, hardenErr(err))
			return
		}
		f := r.URL.Query().Get("format")
		b, ct, err := h.Render(sc, f)
		if err != nil {
			writeErr(w, Errf(http.StatusBadRequest, "%s", err.Error()))
			return
		}
		ext := map[string]string{"application/pdf": "pdf", "application/json": "json"}[ct]
		if ext == "" {
			ext = "md"
		}
		name := fmt.Sprintf("hardening-%s-%s.%s", s.Cfg.ServerName, sc.StartedAt.Format("20060102-1504"), ext)
		w.Header().Set("Content-Type", ct)
		w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(name, `"`, "")+`"`)
		w.Write(b)
	})
	s.Route("GET /harden/checks", auth.ScopeRead, func(r *http.Request) (any, error) { return h.Checks(r.Context()), nil })

	s.Route("POST /harden/fixes", auth.ScopeHarden, func(r *http.Request) (any, error) {
		var q fixReq
		if err := Decode(r, &q); err != nil {
			return nil, err
		}
		if q.CheckID == "" && !q.All {
			return nil, Errf(http.StatusBadRequest, `give "check_id" or "all": true`)
		}
		if !q.DryRun && !q.Confirm {
			return nil, Errf(http.StatusBadRequest,
				"applying fixes needs \"confirm\": true; review the diff first with \"dry_run\": true")
		}
		if q.All {
			rs, err := h.FixAll(r.Context(), q.Severity, q.DryRun)
			if err != nil {
				return nil, Errf(http.StatusBadRequest, "%s", err.Error())
			}
			return rs, nil
		}
		res, err := h.Fix(r.Context(), q.CheckID, q.DryRun)
		if err != nil {
			return nil, hardenErr(err)
		}
		return []harden.FixResult{res}, nil
	})
	s.Route("GET /harden/fixes", auth.ScopeRead, func(r *http.Request) (any, error) {
		return h.ListFixes(r.Context(), hardenLimit(r))
	})
	s.Route("POST /harden/fixes/{id}/revert", auth.ScopeHarden, func(r *http.Request) (any, error) {
		f, err := h.Revert(r.Context(), r.PathValue("id"))
		return f, hardenErr(err)
	})

	s.Route("GET /harden/ignores", auth.ScopeRead, func(r *http.Request) (any, error) { return h.Ignores(r.Context()) })
	s.Route("POST /harden/ignores", auth.ScopeHarden, func(r *http.Request) (any, error) {
		var q struct {
			CheckID string `json:"check_id"`
			Reason  string `json:"reason"`
		}
		if err := Decode(r, &q); err != nil {
			return nil, err
		}
		ig, err := h.Ignore(r.Context(), q.CheckID, q.Reason)
		if err != nil && !errors.Is(err, harden.ErrUnknownCheck) {
			return nil, Errf(http.StatusBadRequest, "%s", err.Error())
		}
		return ig, hardenErr(err)
	})
	s.Route("DELETE /harden/ignores/{id}", auth.ScopeHarden, func(r *http.Request) (any, error) {
		err := h.Unignore(r.Context(), r.PathValue("id"))
		if err != nil && !errors.Is(err, db.ErrNotFound) {
			return nil, Errf(http.StatusConflict, "%s", err.Error())
		}
		return nil, hardenErr(err)
	})
}
