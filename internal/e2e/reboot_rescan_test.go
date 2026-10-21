package e2e

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/updates"
)

// A pending reboot comes from the daily Windows Update scan: the console
// scans again after a restart job, and every few hours while a reboot is
// pending, so that a restarted endpoint stops showing it.
func TestRebootRescans(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	now := time.Now()
	for _, m := range []string{"winupdate", "inventory", "reboot"} {
		publishTo(t, e.store, filepath.Join(repoRoot(t), "modules", m))
	}
	agent := func(name string, scanned time.Time, reboot bool) string {
		id := e.addWindowsAgent(t, name)
		e.store.UpdateAgentSeen(ctx, e.tenant, id, &store.HostInfo{Hostname: name, OS: "windows", Arch: "amd64", OSFamily: "client"}, now, nil)
		e.store.PutUpdateStatus(ctx, store.UpdateStatus{TenantID: e.tenant, AgentID: id, Source: updates.SourceWindows, ScannedAt: scanned,
			Data: []byte(`{"managed_by":"none","updates":[]}`), ManagedBy: "none", Reboot: reboot})
		return id
	}
	restarted := agent("PC-RESTARTED", now.Add(-time.Hour), true)
	waiting := agent("PC-WAITING", now.Add(-time.Hour), true)
	old := agent("PC-OLD-SCAN", now.Add(-4*time.Hour), true)
	clean := agent("PC-CLEAN", now.Add(-20*time.Hour), false)

	// PC-RESTARTED: a restart job ended 20 minutes ago.
	mods, _ := e.store.ListModules(ctx)
	var reboot store.Module
	for _, m := range mods {
		if m.ID == "reboot" {
			reboot = m
		}
	}
	job := store.Job{TenantID: e.tenant, ID: ids.NewUUID(), AgentID: restarted, Module: "reboot", ModuleVersion: reboot.Version,
		Action: "reboot", Params: []byte("{}"), Envelope: []byte("x"), CreatedBy: "operator:admin", ExpiresAt: now.Add(time.Hour),
		CreatedAt: now.Add(-25 * time.Minute)}
	if err := e.store.CreateJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	e.store.UpdateJob(ctx, e.tenant, restarted, job.ID, store.JobUpdate{State: store.JobSucceeded}, now.Add(-20*time.Minute))

	e.web.RunRebootRescans(ctx)
	queued := func(id string) (scans, invs int) {
		jobs, _ := e.store.ListJobs(ctx, e.tenant, id, 50)
		for _, j := range jobs {
			if j.State == store.JobQueued && j.Module == "winupdate" && j.Action == "scan" {
				scans++
			}
			if j.State == store.JobQueued && j.Module == "inventory" {
				invs++
			}
		}
		return
	}
	for _, c := range []struct {
		name        string
		id          string
		scans, invs int
	}{{"restarted", restarted, 1, 1}, {"waiting", waiting, 0, 0}, {"old scan", old, 1, 0}, {"clean", clean, 0, 0}} {
		if s, i := queued(c.id); s != c.scans || i != c.invs {
			t.Errorf("%s: %d scans, %d inventories; want %d, %d", c.name, s, i, c.scans, c.invs)
		}
	}
	// Queued scans count: no second round.
	e.web.RunRebootRescans(ctx)
	if s, _ := queued(restarted); s != 1 {
		t.Errorf("restarted: %d scans after a second round", s)
	}
	if s, _ := queued(old); s != 1 {
		t.Errorf("old scan: %d scans after a second round", s)
	}
}
