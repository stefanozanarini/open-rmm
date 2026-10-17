package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"google.golang.org/protobuf/proto"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/console/audit"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/modules"
	"github.com/stefanozanarini/open-rmm/internal/signing"
	"github.com/stefanozanarini/open-rmm/modules/sdk"
)

func loadSigner(path string) (*signing.Signer, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- key file chosen by the operator
	if err != nil {
		return nil, err
	}
	key, err := signing.ParsePrivateKey(string(raw))
	if err != nil {
		return nil, err
	}
	return signing.NewSigner(key)
}

// sdkFiles returns the SDK files a module needs, by archive path. They come
// from sdkDir when set, otherwise from the copy embedded in this binary.
func sdkFiles(m *modules.Manifest, sdkDir string) (map[string][]byte, error) {
	need := map[string]string{}
	for _, ep := range m.Entrypoints {
		switch ep.Type {
		case modules.TypePowerShell:
			need["_sdk/OpenRmm.psm1"] = "powershell/OpenRmm.psm1"
		case modules.TypeShell:
			need["_sdk/openrmm.sh"] = "sh/openrmm.sh"
		}
	}
	var src fs.FS = sdk.FS
	if sdkDir != "" {
		src = os.DirFS(sdkDir)
	}
	out := map[string][]byte{}
	for dst, p := range need {
		b, err := fs.ReadFile(src, p)
		if err != nil {
			return nil, fmt.Errorf("SDK: %w", err)
		}
		out[dst] = b
	}
	return out, nil
}

// moduleSign packs and signs a module directory. It needs no database: it is
// meant to run on the offline machine that holds the module release key.
func moduleSign(args []string) error {
	fs := flag.NewFlagSet("module sign", flag.ContinueOnError)
	dir := fs.String("dir", "", "module source directory (contains manifest.json)")
	keyPath := fs.String("key", "", "module release private key")
	out := fs.String("out", "", "bundle output file (default <id>-<version>.ormm)")
	sdkDir := fs.String("sdk", "", "SDK directory (default: the SDK embedded in openrmm-admin)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *keyPath == "" {
		return errors.New("-dir and -key are required")
	}
	raw, err := os.ReadFile(filepath.Join(*dir, "manifest.json"))
	if err != nil {
		return err
	}
	var m modules.Manifest
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return fmt.Errorf("manifest.json: %w", err)
	}
	extra, err := sdkFiles(&m, *sdkDir)
	if err != nil {
		return err
	}
	archive, err := modules.Pack(&m, *dir, extra)
	if err != nil {
		return err
	}
	signer, err := loadSigner(*keyPath)
	if err != nil {
		return err
	}
	b, err := modules.SignBundle(signer, &m, archive)
	if err != nil {
		return err
	}
	data, err := json.Marshal(b)
	if err != nil {
		return err
	}
	if *out == "" {
		*out = m.ID + "-" + m.Version + ".ormm"
	}
	if err := writeNew(*out, data); err != nil {
		return err
	}
	fmt.Printf("%s %s signed with key %s\nfiles: %d, archive: %d bytes\nmanifest sha256: %s\nwritten to %s\n",
		m.ID, m.Version, signer.KeyID(), len(m.Files), len(archive), hex.EncodeToString(modules.ManifestHash(b.Manifest)), *out)
	return nil
}

// trustedModuleKeys reads OPENRMM_MODULE_KEYS (comma-separated "ed25519:...").
func trustedModuleKeys() (*signing.Keyring, error) {
	k := signing.NewKeyring()
	for _, s := range strings.Split(os.Getenv("OPENRMM_MODULE_KEYS"), ",") {
		if strings.TrimSpace(s) == "" {
			continue
		}
		pub, err := signing.ParsePublicKey(s)
		if err != nil {
			return nil, fmt.Errorf("OPENRMM_MODULE_KEYS: %w", err)
		}
		if _, err := k.Add(pub, signing.DomainModuleManifest); err != nil {
			return nil, err
		}
	}
	if k.Len() == 0 {
		return nil, errors.New("OPENRMM_MODULE_KEYS is not set: the console verifies modules before publishing them")
	}
	return k, nil
}

func modulePublish(ctx context.Context, db store.Store, args []string) error {
	fs := flag.NewFlagSet("module publish", flag.ContinueOnError)
	file := fs.String("file", "", "bundle (.ormm) produced by module sign")
	if err := fs.Parse(args); err != nil {
		return err
	}
	keys, err := trustedModuleKeys()
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*file) // #nosec G304 -- bundle chosen by the operator
	if err != nil {
		return err
	}
	var b modules.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return fmt.Errorf("bundle: %w", err)
	}
	v, err := b.Verify(keys)
	if err != nil {
		return err
	}
	// Extracting in a scratch directory exercises the same checks as the
	// agent, so a broken bundle never reaches the endpoints.
	tmp, err := os.MkdirTemp("", "openrmm-module-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err := modules.Extract(v.Manifest, b.Archive, filepath.Join(tmp, "x")); err != nil {
		return err
	}
	if err := db.PutModule(ctx, store.Module{
		ID: v.Manifest.ID, Version: v.Manifest.Version, Description: v.Manifest.Description,
		KeyID: b.KeyID, Manifest: b.Manifest, Signature: b.Signature, ManifestSHA256: v.ManifestHash,
		Archive: b.Archive, UploadedBy: "admin-cli",
	}); err != nil {
		return err
	}
	fmt.Printf("published %s %s (manifest sha256 %s)\n", v.Manifest.ID, v.Manifest.Version, hex.EncodeToString(v.ManifestHash))
	return nil
}

func moduleList(ctx context.Context, db store.Store) error {
	mods, err := db.ListModules(ctx)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "MODULE\tVERSION\tKEY\tUPLOADED\tDESCRIPTION")
	for _, m := range mods {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", m.ID, m.Version, m.KeyID, m.UploadedAt.Local().Format(time.DateTime), m.Description)
	}
	return w.Flush()
}

// jobRun signs and queues a job.
// TODO(fase 0): signing moves to openrmm-signer, with MFA verified per job.
func jobRun(ctx context.Context, db store.Store, args []string) error {
	fs := flag.NewFlagSet("job run", flag.ContinueOnError)
	tenant := fs.String("tenant", "", "tenant ID")
	agent := fs.String("agent", "", "agent ID")
	module := fs.String("module", "", "module ID")
	version := fs.String("version", "", "module version")
	action := fs.String("action", "", "module action")
	params := fs.String("params", "{}", "action parameters (JSON object)")
	scriptFile := fs.String("script-file", "", "for the script module: read params.script from this file")
	ttl := fs.Duration("ttl", time.Hour, "time the job stays deliverable")
	keyPath := fs.String("key", "", "job signing private key")
	wait := fs.Bool("wait", false, "wait for the result")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !ids.IsUUID(*tenant) || !ids.IsUUID(*agent) || *module == "" || *version == "" || *action == "" || *keyPath == "" {
		return errors.New("-tenant, -agent, -module, -version, -action and -key are required")
	}
	if *ttl <= 0 || *ttl > 24*time.Hour {
		return errors.New("-ttl must be between 0 and 24h")
	}
	var p map[string]any
	if err := json.Unmarshal([]byte(*params), &p); err != nil {
		return fmt.Errorf("-params must be a JSON object: %w", err)
	}
	if *scriptFile != "" {
		s, err := os.ReadFile(*scriptFile) // #nosec G304 -- script chosen by the operator
		if err != nil {
			return err
		}
		p["script"] = string(s)
	}
	paramsJSON, err := json.Marshal(p)
	if err != nil {
		return err
	}
	a, err := db.GetAgent(ctx, *tenant, *agent)
	if err != nil {
		return fmt.Errorf("agent: %w", err)
	}
	if a.Status != store.AgentActive {
		return fmt.Errorf("agent is %s: only approved agents receive jobs", a.Status)
	}
	mod, err := db.GetModule(ctx, *module, *version)
	if err != nil {
		return fmt.Errorf("module %s %s: %w", *module, *version, err)
	}
	m, err := modules.ParseManifest(mod.Manifest)
	if err != nil {
		return err
	}
	if _, ok := m.Actions[*action]; !ok {
		return fmt.Errorf("module %s has no action %q", m.ID, *action)
	}
	signer, err := loadSigner(*keyPath)
	if err != nil {
		return err
	}
	now := time.Now()
	job := &openrmmv1.Job{
		JobId: ids.NewUUID(), TenantId: *tenant, AgentId: *agent,
		Module: m.ID, ModuleVersion: m.Version, ModuleSha256: mod.ManifestSHA256,
		Action: *action, ParamsJson: paramsJSON,
		NotBeforeUnix: now.Add(-time.Minute).Unix(), ExpiresUnix: now.Add(*ttl).Unix(),
		Nonce: ids.Random(16),
	}
	payload, err := proto.Marshal(job)
	if err != nil {
		return err
	}
	env, err := proto.Marshal(&openrmmv1.SignedEnvelope{KeyId: signer.KeyID(), Payload: payload,
		Signature: signer.Sign(signing.DomainJob, payload)})
	if err != nil {
		return err
	}
	if err := db.CreateJob(ctx, store.Job{
		TenantID: *tenant, ID: job.GetJobId(), AgentID: *agent, Module: m.ID, ModuleVersion: m.Version,
		Action: *action, Params: paramsJSON, Envelope: env, CreatedBy: "admin-cli", ExpiresAt: now.Add(*ttl),
	}); err != nil {
		return err
	}
	// The audit trail keeps the full parameters (for the script module, the
	// script text itself).
	if _, err := db.AppendAudit(ctx, audit.Event{TenantID: *tenant, Actor: "admin-cli", Action: "job.created",
		Target: job.GetJobId(), Details: map[string]any{"agent": *agent, "module": m.ID, "version": m.Version,
			"action": *action, "params": json.RawMessage(paramsJSON), "signing_key": signer.KeyID()}}); err != nil {
		return err
	}
	fmt.Println(job.GetJobId())
	if !*wait {
		return nil
	}
	return waitJob(ctx, db, *tenant, job.GetJobId(), *ttl)
}

func waitJob(ctx context.Context, db store.Store, tenant, id string, limit time.Duration) error {
	deadline := time.Now().Add(limit)
	last := store.JobState("")
	for time.Now().Before(deadline) {
		j, err := db.GetJob(ctx, tenant, id)
		if err != nil {
			return err
		}
		if j.State != last {
			fmt.Fprintf(os.Stderr, "%s %s %d%% %s\n", time.Now().Format(time.TimeOnly), j.State, j.Progress, j.Message)
			last = j.State
		}
		if j.State.Final() {
			return printJob(j)
		}
		time.Sleep(time.Second)
	}
	return errors.New("timed out waiting for the job")
}

func printJob(j store.Job) error {
	fmt.Printf("job:      %s\nagent:    %s\nmodule:   %s %s / %s\nstate:    %s\ncreated:  %s\n",
		j.ID, j.AgentID, j.Module, j.ModuleVersion, j.Action, j.State, j.CreatedAt.Local().Format(time.DateTime))
	if j.FinishedAt != nil {
		fmt.Printf("finished: %s\n", j.FinishedAt.Local().Format(time.DateTime))
	}
	if j.Error != "" {
		fmt.Printf("error:\n%s\n", j.Error)
	}
	if len(j.Result) > 0 {
		var v any
		if json.Unmarshal(j.Result, &v) == nil {
			pretty, _ := json.MarshalIndent(v, "", "  ")
			fmt.Printf("result:\n%s\n", pretty)
		}
	}
	if j.State == store.JobFailed || j.State == store.JobRejected || j.State == store.JobExpired {
		return fmt.Errorf("job %s", j.State)
	}
	return nil
}

func jobShow(ctx context.Context, db store.Store, args []string) error {
	fs := flag.NewFlagSet("job show", flag.ContinueOnError)
	tenant := fs.String("tenant", "", "tenant ID")
	id := fs.String("id", "", "job ID")
	wait := fs.Bool("wait", false, "wait until the job is finished")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *wait {
		return waitJob(ctx, db, *tenant, *id, 24*time.Hour)
	}
	j, err := db.GetJob(ctx, *tenant, *id)
	if err != nil {
		return err
	}
	return printJob(j)
}

func jobList(ctx context.Context, db store.Store, args []string) error {
	fs := flag.NewFlagSet("job list", flag.ContinueOnError)
	tenant := fs.String("tenant", "", "tenant ID")
	agent := fs.String("agent", "", "only jobs of this agent")
	limit := fs.Int("limit", 50, "maximum number of jobs")
	if err := fs.Parse(args); err != nil {
		return err
	}
	jobs, err := db.ListJobs(ctx, *tenant, *agent, *limit)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "JOB\tAGENT\tMODULE\tACTION\tSTATE\tCREATED")
	for _, j := range jobs {
		fmt.Fprintf(w, "%s\t%s\t%s %s\t%s\t%s\t%s\n", j.ID, j.AgentID, j.Module, j.ModuleVersion, j.Action, j.State,
			j.CreatedAt.Local().Format(time.DateTime))
	}
	return w.Flush()
}
