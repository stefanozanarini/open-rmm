package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/audit"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/release"
	"github.com/stefanozanarini/open-rmm/internal/signing"
)

// releaseBundle is the distributable form of a signed release (.orel).
type releaseBundle struct {
	KeyID     string            `json:"key_id"`
	Manifest  []byte            `json:"manifest"`
	Signature []byte            `json:"signature"`
	Files     map[string][]byte `json:"files"`
}

// releaseSign signs a release. Meant for the offline machine holding the
// agent release key.
func releaseSign(args []string) error {
	fs := flag.NewFlagSet("release sign", flag.ContinueOnError)
	version := fs.String("version", "", "release version x.y.z (must match the version built into the binaries)")
	platform := fs.String("platform", "", "GOOS/GOARCH, e.g. windows/amd64")
	agentPath := fs.String("agent", "", "agent executable")
	wdPath := fs.String("watchdog", "", "watchdog executable")
	keyPath := fs.String("key", "", "agent release private key")
	notes := fs.String("notes", "", "release notes")
	out := fs.String("out", "", "output file (default openrmm-<version>-<os>-<arch>.orel)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *version == "" || *platform == "" || *agentPath == "" || *wdPath == "" || *keyPath == "" {
		return errors.New("-version, -platform, -agent, -watchdog and -key are required")
	}
	goos, _, _ := strings.Cut(*platform, "/")
	files := map[string][]byte{}
	m := &release.Manifest{Version: *version, Platform: *platform, ReleasedAt: time.Now().UTC(), Notes: *notes}
	for name, p := range map[string]string{release.AgentFile(goos): *agentPath, release.WatchdogFile(goos): *wdPath} {
		data, err := os.ReadFile(p) // #nosec G304 -- operator-chosen file
		if err != nil {
			return err
		}
		files[name] = data
		m.Files = append(m.Files, release.HashFile(name, data))
	}
	signer, err := loadSigner(*keyPath)
	if err != nil {
		return err
	}
	raw, sig, err := release.Sign(signer, m)
	if err != nil {
		return err
	}
	data, err := json.Marshal(releaseBundle{KeyID: signer.KeyID(), Manifest: raw, Signature: sig, Files: files})
	if err != nil {
		return err
	}
	if *out == "" {
		*out = fmt.Sprintf("openrmm-%s-%s.orel", *version, strings.ReplaceAll(*platform, "/", "-"))
	}
	if err := writeNew(*out, data); err != nil {
		return err
	}
	fmt.Printf("release %s %s signed with key %s, written to %s\n", *version, *platform, signer.KeyID(), *out)
	return nil
}

func trustedReleaseKeys() (*signing.Keyring, error) {
	k := signing.NewKeyring()
	for _, s := range strings.Split(os.Getenv("OPENRMM_RELEASE_KEYS"), ",") {
		if strings.TrimSpace(s) == "" {
			continue
		}
		pub, err := signing.ParsePublicKey(s)
		if err != nil {
			return nil, fmt.Errorf("OPENRMM_RELEASE_KEYS: %w", err)
		}
		if _, err := k.Add(pub, signing.DomainAgentRelease); err != nil {
			return nil, err
		}
	}
	if k.Len() == 0 {
		return nil, errors.New("OPENRMM_RELEASE_KEYS is not set: the console verifies releases before publishing them")
	}
	return k, nil
}

func releasePublish(ctx context.Context, db store.Store, args []string) error {
	fs := flag.NewFlagSet("release publish", flag.ContinueOnError)
	file := fs.String("file", "", "release bundle (.orel)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	keys, err := trustedReleaseKeys()
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*file) // #nosec G304 -- operator-chosen file
	if err != nil {
		return err
	}
	var b releaseBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return fmt.Errorf("bundle: %w", err)
	}
	m, err := release.Verify(keys, b.KeyID, b.Manifest, b.Signature)
	if err != nil {
		return err
	}
	if len(b.Files) != len(m.Files) {
		return errors.New("bundle files do not match the manifest")
	}
	for _, f := range m.Files {
		if err := f.CheckFile(b.Files[f.Name]); err != nil {
			return err
		}
	}
	if err := db.PutRelease(ctx, store.Release{Version: m.Version, Platform: m.Platform, KeyID: b.KeyID,
		Manifest: b.Manifest, Signature: b.Signature, Notes: m.Notes, PublishedBy: "admin-cli", Files: b.Files}); err != nil {
		return err
	}
	fmt.Printf("published agent release %s for %s\n", m.Version, m.Platform)
	return nil
}

func releaseList(ctx context.Context, db store.Store, args []string) error {
	fs := flag.NewFlagSet("release list", flag.ContinueOnError)
	tenant := fs.String("tenant", "", "also show the targets of this tenant")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rels, err := db.ListReleases(ctx)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "VERSION\tPLATFORM\tKEY\tPUBLISHED\tNOTES")
	for _, r := range rels {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", r.Version, r.Platform, r.KeyID, r.PublishedAt.Local().Format(time.DateTime), r.Notes)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if *tenant == "" {
		return nil
	}
	targets, err := db.ListReleaseTargets(ctx, *tenant)
	if err != nil {
		return err
	}
	fmt.Println()
	w = tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "RING\tPLATFORM\tTARGET VERSION\tSET")
	for _, t := range targets {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s by %s\n", t.Ring, t.Platform, t.Version, t.UpdatedAt.Local().Format(time.DateTime), t.UpdatedBy)
	}
	return w.Flush()
}

func releaseTarget(ctx context.Context, db store.Store, args []string) error {
	fs := flag.NewFlagSet("release target", flag.ContinueOnError)
	tenant := fs.String("tenant", "", "tenant ID")
	ring := fs.String("ring", "", "pilot or broad")
	platform := fs.String("platform", "", "GOOS/GOARCH")
	version := fs.String("version", "", "published release version")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !ids.IsUUID(*tenant) || !store.ValidRing(*ring) || *platform == "" || *version == "" {
		return errors.New("-tenant, -ring (pilot|broad), -platform and -version are required")
	}
	if err := db.SetReleaseTarget(ctx, store.ReleaseTarget{TenantID: *tenant, Ring: *ring, Platform: *platform,
		Version: *version, UpdatedBy: "admin-cli"}); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("release %s for %s is not published", *version, *platform)
		}
		return err
	}
	if _, err := db.AppendAudit(ctx, audit.Event{TenantID: *tenant, Actor: "admin-cli", Action: "release.target_set",
		Target: *ring, Details: map[string]any{"platform": *platform, "version": *version}}); err != nil {
		return err
	}
	fmt.Printf("ring %s on %s will update to %s\n", *ring, *platform, *version)
	return nil
}

func agentsRing(ctx context.Context, db store.Store, args []string) error {
	fs := flag.NewFlagSet("agents ring", flag.ContinueOnError)
	tenant := fs.String("tenant", "", "tenant ID")
	agent := fs.String("agent", "", "agent ID")
	ring := fs.String("ring", "", "pilot or broad")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !store.ValidRing(*ring) {
		return errors.New("-ring must be pilot or broad")
	}
	if err := db.SetAgentRing(ctx, *tenant, *agent, *ring); err != nil {
		return err
	}
	_, err := db.AppendAudit(ctx, audit.Event{TenantID: *tenant, Actor: "admin-cli", Action: "agent.ring_set", Target: *agent,
		Details: map[string]any{"ring": *ring}})
	return err
}
