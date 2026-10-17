// Command openrmm-admin bootstraps and administers a console.
//
//	openrmm-admin pki init -dir DIR -gateway-dns agent.example.com
//	openrmm-admin db migrate
//	openrmm-admin tenant create -name "Cliente"
//	openrmm-admin token create -tenant UUID [-ttl 24h] [-max-uses 1] [-auto-approve] [-description ...]
//	openrmm-admin token revoke -id UUID
//	openrmm-admin agents list -tenant UUID
//	openrmm-admin agents approve -tenant UUID -agent UUID
//	openrmm-admin agents reject -tenant UUID -agent UUID     (alias of revoke)
//	openrmm-admin agents revoke -tenant UUID -agent UUID
//	openrmm-admin audit verify -tenant UUID
//	openrmm-admin signing keygen -out FILE
//	openrmm-admin module sign -dir DIR -key FILE [-out FILE] [-sdk modules/sdk]
//	openrmm-admin module publish -file BUNDLE      (needs OPENRMM_MODULE_KEYS)
//	openrmm-admin module list
//	openrmm-admin job run -tenant UUID -agent UUID -module ID -version X.Y.Z -action NAME -key FILE
//	                      [-params JSON] [-script-file FILE] [-ttl 1h] [-wait]
//	openrmm-admin job show -tenant UUID -id UUID [-wait]
//	openrmm-admin job list -tenant UUID [-agent UUID]
//	openrmm-admin release sign -version X.Y.Z -platform OS/ARCH -agent FILE -watchdog FILE -key FILE
//	openrmm-admin release publish -file BUNDLE     (needs OPENRMM_RELEASE_KEYS)
//	openrmm-admin release list [-tenant UUID]
//	openrmm-admin release target -tenant UUID -ring pilot|broad -platform OS/ARCH -version X.Y.Z
//	openrmm-admin agents ring -tenant UUID -agent UUID -ring pilot|broad
//
// Database commands read the connection string from OPENRMM_DATABASE_URL.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/audit"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/pki"
	"github.com/stefanozanarini/open-rmm/internal/signing"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "openrmm-admin:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 2 {
		return errors.New("usage: openrmm-admin <area> <command> [flags] (see source header)")
	}
	area, cmd, rest := args[0], args[1], args[2:]
	switch area + " " + cmd {
	case "pki init":
		return pkiInit(rest)
	case "signing keygen":
		return signingKeygen(rest)
	case "module sign":
		return moduleSign(rest)
	case "release sign":
		return releaseSign(rest)
	}
	ctx := context.Background()
	url := os.Getenv("OPENRMM_DATABASE_URL")
	if url == "" {
		return errors.New("OPENRMM_DATABASE_URL is not set")
	}
	db, err := store.OpenPostgres(ctx, url)
	if err != nil {
		return err
	}
	defer db.Close()
	switch area + " " + cmd {
	case "db migrate":
		return db.Migrate(ctx)
	case "tenant create":
		return tenantCreate(ctx, db, rest)
	case "token create":
		return tokenCreate(ctx, db, rest)
	case "token revoke":
		return tokenRevoke(ctx, db, rest)
	case "agents list":
		return agentsList(ctx, db, rest)
	case "agents approve":
		return agentsApprove(ctx, db, rest)
	case "agents revoke", "agents reject":
		return agentsRevoke(ctx, db, rest)
	case "audit verify":
		return auditVerify(ctx, db, rest)
	case "module publish":
		return modulePublish(ctx, db, rest)
	case "module list":
		return moduleList(ctx, db)
	case "job run":
		return jobRun(ctx, db, rest)
	case "job show":
		return jobShow(ctx, db, rest)
	case "job list":
		return jobList(ctx, db, rest)
	case "release publish":
		return releasePublish(ctx, db, rest)
	case "release list":
		return releaseList(ctx, db, rest)
	case "release target":
		return releaseTarget(ctx, db, rest)
	case "agents ring":
		return agentsRing(ctx, db, rest)
	}
	return fmt.Errorf("unknown command %q", area+" "+cmd)
}

// writeNew writes a file that must not already exist, readable only by the
// current user.
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- path chosen by the operator
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return errors.Join(err, f.Close(), os.Remove(path))
	}
	return f.Close()
}

func pkiInit(args []string) error {
	fs := flag.NewFlagSet("pki init", flag.ContinueOnError)
	dir := fs.String("dir", "", "output directory (must not contain existing PKI files)")
	dns := fs.String("gateway-dns", "", "comma-separated DNS names of the agents endpoint")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *dns == "" {
		return errors.New("-dir and -gateway-dns are required")
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	now := time.Now()
	root, err := pki.NewRootCA("open-rmm root CA", now)
	if err != nil {
		return err
	}
	agentsCA, err := pki.NewIntermediateCA(root, "open-rmm agents CA", now)
	if err != nil {
		return err
	}
	names := strings.Split(*dns, ",")
	srv, srvKey, err := agentsCA.IssueServer(names, now)
	if err != nil {
		return err
	}
	rootKey, err := pki.EncodeKeyPEM(root.Key)
	if err != nil {
		return err
	}
	caKey, err := pki.EncodeKeyPEM(agentsCA.Key)
	if err != nil {
		return err
	}
	gwKey, err := pki.EncodeKeyPEM(srvKey)
	if err != nil {
		return err
	}
	files := []struct {
		name string
		data []byte
	}{
		{"root-ca.crt", pki.EncodeCertPEM(root.Cert)},
		{"root-ca.key", rootKey},
		{"agents-ca.crt", pki.EncodeCertPEM(agentsCA.Cert)},
		{"agents-ca.key", caKey},
		{"gateway.crt", pki.EncodeCertPEM(srv, agentsCA.Cert)},
		{"gateway.key", gwKey},
	}
	for _, f := range files {
		if err := writeNew(filepath.Join(*dir, f.name), f.data); err != nil {
			return err
		}
	}
	fmt.Printf("PKI created in %s\n", *dir)
	fmt.Printf("root CA SHA-256 fingerprint: %s\n", pki.Fingerprint(root.Cert))
	fmt.Println()
	fmt.Println("IMPORTANT: move root-ca.key offline (e.g. an encrypted USB key in a safe).")
	fmt.Println("It is only needed to issue a new agents CA. Distribute root-ca.crt to agents.")
	return nil
}

func signingKeygen(args []string) error {
	fs := flag.NewFlagSet("signing keygen", flag.ContinueOnError)
	out := fs.String("out", "", "private key output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("-out is required")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := writeNew(*out, []byte(signing.EncodePrivateKey(priv)+"\n")); err != nil {
		return err
	}
	fmt.Printf("key id:     %s\npublic key: %s\n", signing.KeyID(pub), signing.EncodePublicKey(pub))
	return nil
}

func tenantCreate(ctx context.Context, db store.Store, args []string) error {
	fs := flag.NewFlagSet("tenant create", flag.ContinueOnError)
	name := fs.String("name", "", "tenant name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("-name is required")
	}
	t := store.Tenant{ID: ids.NewUUID(), Name: *name}
	if err := db.CreateTenant(ctx, t); err != nil {
		return err
	}
	if _, err := db.AppendAudit(ctx, audit.Event{TenantID: t.ID, Actor: "admin-cli", Action: "tenant.created",
		Target: t.ID, Details: map[string]any{"name": t.Name}}); err != nil {
		return err
	}
	fmt.Println(t.ID)
	return nil
}

func tokenCreate(ctx context.Context, db store.Store, args []string) error {
	fs := flag.NewFlagSet("token create", flag.ContinueOnError)
	tenant := fs.String("tenant", "", "tenant ID")
	ttl := fs.Duration("ttl", 24*time.Hour, "validity")
	maxUses := fs.Int("max-uses", 1, "number of enrollments allowed")
	desc := fs.String("description", "", "free text, e.g. 'GPO sede Bologna'")
	autoApprove := fs.Bool("auto-approve", false, "agents enrolled with this token are active at once, without operator approval")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !ids.IsUUID(*tenant) {
		return errors.New("-tenant must be a tenant UUID")
	}
	if *ttl <= 0 || *ttl > 90*24*time.Hour {
		return errors.New("-ttl must be between 0 and 90 days")
	}
	if *maxUses < 1 || *maxUses > 100_000 {
		return errors.New("-max-uses must be between 1 and 100000")
	}
	secret := ids.NewSecret(32)
	t := store.EnrollmentToken{ID: ids.NewUUID(), TenantID: *tenant, Description: *desc,
		MaxUses: *maxUses, ExpiresAt: time.Now().Add(*ttl), AutoApprove: *autoApprove}
	if err := db.CreateEnrollmentToken(ctx, t, store.HashToken(secret)); err != nil {
		return err
	}
	if _, err := db.AppendAudit(ctx, audit.Event{TenantID: t.TenantID, Actor: "admin-cli", Action: "enrollment_token.created",
		Target: t.ID, Details: map[string]any{"max_uses": t.MaxUses, "expires_at": t.ExpiresAt.UTC().Format(time.RFC3339),
			"description": t.Description, "auto_approve": t.AutoApprove}}); err != nil {
		return err
	}
	approval := "required (agents wait in 'pending' until approved)"
	if t.AutoApprove {
		approval = "automatic"
	}
	fmt.Printf("token id: %s\nexpires:  %s\nmax uses: %d\napproval: %s\n\n%s\n\n(the token is shown only once)\n",
		t.ID, t.ExpiresAt.Format(time.RFC3339), t.MaxUses, approval, secret)
	return nil
}

func tokenRevoke(ctx context.Context, db store.Store, args []string) error {
	fs := flag.NewFlagSet("token revoke", flag.ContinueOnError)
	id := fs.String("id", "", "token ID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return db.RevokeEnrollmentToken(ctx, *id)
}

func agentsList(ctx context.Context, db store.Store, args []string) error {
	fs := flag.NewFlagSet("agents list", flag.ContinueOnError)
	tenant := fs.String("tenant", "", "tenant ID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	agents, err := db.ListAgents(ctx, *tenant)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "AGENT\tHOSTNAME\tOS\tVERSION\tSTATUS\tLAST SEEN")
	for _, a := range agents {
		seen := "-"
		if a.LastSeenAt != nil {
			seen = a.LastSeenAt.Local().Format(time.DateTime)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", a.ID, a.Host.Hostname, a.Host.OSVersion, a.Host.AgentVersion, a.Status, seen)
	}
	return w.Flush()
}

func agentsApprove(ctx context.Context, db store.Store, args []string) error {
	fs := flag.NewFlagSet("agents approve", flag.ContinueOnError)
	tenant := fs.String("tenant", "", "tenant ID")
	agent := fs.String("agent", "", "agent ID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	a, err := db.GetAgent(ctx, *tenant, *agent)
	if err != nil {
		return err
	}
	if err := db.ApproveAgent(ctx, *tenant, *agent, "admin-cli", time.Now()); err != nil {
		return err
	}
	_, err = db.AppendAudit(ctx, audit.Event{TenantID: *tenant, Actor: "admin-cli", Action: "agent.approved", Target: *agent,
		Details: map[string]any{"hostname": a.Host.Hostname, "machine_id": a.Host.MachineID}})
	if err == nil {
		fmt.Printf("approved %s (%s)\n", a.ID, a.Host.Hostname)
	}
	return err
}

func agentsRevoke(ctx context.Context, db store.Store, args []string) error {
	fs := flag.NewFlagSet("agents revoke", flag.ContinueOnError)
	tenant := fs.String("tenant", "", "tenant ID")
	agent := fs.String("agent", "", "agent ID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := db.SetAgentStatus(ctx, *tenant, *agent, store.AgentRevoked); err != nil {
		return err
	}
	_, err := db.AppendAudit(ctx, audit.Event{TenantID: *tenant, Actor: "admin-cli", Action: "agent.revoked", Target: *agent})
	return err
}

func auditVerify(ctx context.Context, db store.Store, args []string) error {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	tenant := fs.String("tenant", "", "tenant ID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	events, err := db.ListAudit(ctx, *tenant)
	if err != nil {
		return err
	}
	if err := audit.VerifyChain(events); err != nil {
		return fmt.Errorf("audit chain BROKEN: %w", err)
	}
	fmt.Printf("audit chain OK (%d events)\n", len(events))
	return nil
}
