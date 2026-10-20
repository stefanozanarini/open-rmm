package web

import (
	"context"
	"encoding/hex"
	"errors"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/console/audit"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/console/wingetcat"
	"github.com/stefanozanarini/open-rmm/internal/policy"
)

// Automatic collection: every tenant has a policy, kept by the console,
// that schedules the standard collections (policy.BaselineRules) with the
// newest published version of each module. It is updated when modules are
// published and at startup, and the signer signs it without an operator
// because it checks its fixed content. Nobody has to write rules for
// inventory, updates and protection to appear.

// SyncBaselines brings the automatic collection policy of every tenant in
// line with the published modules.
func (s *Server) SyncBaselines(ctx context.Context) error {
	if s.signer == nil {
		return nil
	}
	mods, err := s.store.ListModules(ctx)
	if err != nil {
		return err
	}
	refs := map[string]policy.ModuleRef{}
	for _, m := range mods {
		if cur, ok := refs[m.ID]; !ok || wingetcat.CompareVersions(m.Version, cur.Version) > 0 {
			refs[m.ID] = policy.ModuleRef{Version: m.Version, SHA256: hex.EncodeToString(m.ManifestSHA256)}
		}
	}
	tenants, err := s.store.ListTenants(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, t := range tenants {
		if err := s.syncBaseline(ctx, t.ID, refs); err != nil {
			s.log.Error("automatic collection not updated", "tenant", t.ID, "err", err)
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (s *Server) syncBaseline(ctx context.Context, tenant string, refs map[string]policy.ModuleRef) error {
	p := policy.Baseline(tenant, 1, refs)
	if p == nil {
		return nil
	}
	cur, err := s.store.GetPolicy(ctx, tenant, p.ID)
	switch {
	case err == nil:
		if old, err := policy.Parse(cur.Document); err == nil && policy.SameRules(old, p) {
			return nil
		}
		p.Version = cur.Version + 1
	case !errors.Is(err, store.ErrNotFound):
		return err
	}
	raw, err := p.Canonical()
	if err != nil {
		return err
	}
	resp, err := s.signer.SignBaseline(ctx, &openrmmv1.SignBaselineRequest{TenantId: tenant, PolicyJson: raw})
	if err != nil {
		return err
	}
	if err := s.store.AddPolicyVersion(ctx, store.PolicyVersion{TenantID: tenant, ID: p.ID, Version: p.Version,
		Name: p.Name, AppliesTo: p.AppliesTo, Document: raw, Envelope: resp.GetEnvelope(), CreatedBy: "automatic"}); err != nil {
		return err
	}
	versions := map[string]string{}
	for _, r := range p.Rules {
		versions[r.Module] = r.ModuleVersion
	}
	if _, err := s.store.AppendAudit(ctx, audit.Event{TenantID: tenant, Actor: "console", Action: "policy.automatic",
		Target: p.ID, OccurredAt: s.now(), Details: map[string]any{"version": p.Version, "modules": versions}}); err != nil {
		s.log.Error("audit append failed", "action", "policy.automatic", "err", err)
	}
	s.log.Info("automatic collection updated", "tenant", tenant, "version", p.Version, "rules", len(p.Rules))
	return nil
}

// isBaseline tells whether a policy is the automatic collection, which the
// console maintains and operators do not edit.
func isBaseline(tenant, id string) bool { return id == policy.BaselineID(tenant) }

// syncAfterPublish updates the automatic collection with new module
// versions; a failure is logged and retried by the periodic sync.
func (s *Server) syncAfterPublish(ctx context.Context) {
	if err := s.SyncBaselines(ctx); err != nil {
		s.log.Error("automatic collection after publication", "err", err)
	}
}
