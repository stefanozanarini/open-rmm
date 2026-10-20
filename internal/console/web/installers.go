package web

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/codesign"
	"github.com/stefanozanarini/open-rmm/internal/console/authn"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/release"
)

// Agent installers: openrmm-builder holds the signing key (encrypted with a
// passphrase asked at each use) and builds MSIs preconfigured with this
// console's gateway, root certificate, public keys and a dedicated
// enrollment token. A build needs an Admin's MFA approval, then the
// passphrase.

// AgentInstall is what installers are preconfigured with.
type AgentInstall struct {
	Server      string // gateway address agents dial, host:port
	RootCA      string // root certificate, base64 DER on one line
	JobKeys     string // public keys, "ed25519:..." separated by ","
	ModuleKeys  string
	ReleaseKeys string
	Timestamp   string // RFC 3161 server; "" for none
}

// missing lists the settings an installer cannot be built without.
func (a AgentInstall) missing() []string {
	var out []string
	for _, f := range []struct{ name, v string }{{"OPENRMM_AGENT_SERVER", a.Server}, {"OPENRMM_AGENT_ROOT_CA", a.RootCA},
		{"OPENRMM_AGENT_JOB_KEYS", a.JobKeys}, {"OPENRMM_MODULE_KEYS", a.ModuleKeys}, {"OPENRMM_RELEASE_KEYS", a.ReleaseKeys}} {
		if f.v == "" {
			out = append(out, f.name)
		}
	}
	return out
}

const (
	installerPlatform = "windows/amd64"
	// installerApprovalTTL is how long an MFA approval waits for the
	// passphrase.
	installerApprovalTTL = 5 * time.Minute
	// Tokens preset in installers: many uses, one year, never approving
	// agents by themselves.
	installerTokenUses = 10000
	installerTokenTTL  = 365 * 24 * time.Hour
	maxInstaller       = 512 << 20
)

// installerApproval is an Admin's MFA approval to build one installer.
type installerApproval struct {
	Version string    `json:"version"`
	At      time.Time `json:"at"`
}

type installerView struct {
	store.Installer
	Token *store.EnrollmentToken
}

type installersData struct {
	Builder   bool
	Signing   *openrmmv1.BuilderStatus
	Chain     *codesign.Chain
	Info      codesign.Info
	Expiring  bool
	Versions  []string
	Missing   []string
	Approved  string // version approved and waiting for the passphrase
	List      []installerView
	MinPass   int
	BuilderUp bool
	// ConsoleAdmin manages the console-wide signing key.
	ConsoleAdmin bool
	// Module and agent release keys: the builder's, with their key ids.
	ModuleKey, ModuleKeyID, ReleaseKey, ReleaseKeyID string
	// Bundled: the agent version shipped with the console, published
	// together with its first installer.
	Bundled string
	// NeedKeys: the module and release keys are still to be created.
	NeedKeys bool
}

func grpcMessage(err error) string { return status.Convert(err).Message() }

func (s *Server) handleInstallers(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	ctx := r.Context()
	st := s.builderStatus(ctx)
	d := installersData{Builder: s.builder != nil, Missing: s.installSettings(st).missing(), MinPass: codesign.MinPassphrase,
		ConsoleAdmin: s.consoleAdmin(sessionFrom(ctx).data.Operator)}
	if st != nil {
		d.BuilderUp, d.Signing = true, st
		if ch, err := codesign.ParseChain([]byte(st.GetChainPem()), s.now()); err == nil {
			d.Chain, d.Info, d.Expiring = &ch, ch.LeafInfo(), ch.Expiring(s.now())
		}
		d.ModuleKey, d.ModuleKeyID = st.GetModuleKey(), keyIDOf(st.GetModuleKey())
		d.ReleaseKey, d.ReleaseKeyID = st.GetReleaseKey(), keyIDOf(st.GetReleaseKey())
	}
	rels, err := s.store.ListReleases(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, rel := range rels {
		if rel.Platform == installerPlatform {
			d.Versions = append(d.Versions, rel.Version)
		}
	}
	// With the builder, missing release keys are created on this page, not
	// configured in .env.
	if d.BuilderUp && d.ReleaseKey == "" && (s.agentInstall.ModuleKeys == "" || s.agentInstall.ReleaseKeys == "") {
		d.NeedKeys = true
		var rest []string
		for _, m := range d.Missing {
			if m != "OPENRMM_MODULE_KEYS" && m != "OPENRMM_RELEASE_KEYS" {
				rest = append(rest, m)
			}
		}
		d.Missing = rest
	}
	if d.Bundled = s.unpublishedBundle(ctx, installerPlatform); d.Bundled != "" && d.ReleaseKey != "" {
		d.Versions = append(d.Versions, d.Bundled)
	}
	sort.Slice(d.Versions, func(i, j int) bool { return compareVersions(d.Versions[i], d.Versions[j]) > 0 })
	if a := sessionFrom(ctx).data.InstallerApproval; a != nil && s.now().Sub(a.At) < installerApprovalTTL {
		d.Approved = a.Version
	}
	list, err := s.store.ListInstallers(ctx, t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	tokens, err := s.store.ListEnrollmentTokens(ctx, t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, i := range list {
		v := installerView{Installer: i}
		for k := range tokens {
			if tokens[k].ID == i.TokenID {
				v.Token = &tokens[k]
			}
		}
		d.List = append(d.List, v)
	}
	s.render(w, r, "installers", s.T(r, "Installazione dell'agente"), d)
}

// compareVersions compares x.y.z numerically.
func compareVersions(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x - y
		}
	}
	return len(pa) - len(pb)
}

// ---- code signing ----

func subjectFrom(r *http.Request) *openrmmv1.CertSubject {
	f := func(k string) string { return strings.TrimSpace(r.PostFormValue(k)) }
	return &openrmmv1.CertSubject{CommonName: f("cn"), Organization: f("o"), OrganizationalUnit: f("ou"),
		Locality: f("l"), Province: f("st"), Country: strings.ToUpper(f("c"))}
}

// passphrase returns the new passphrase if both copies match.
func (s *Server) passphrase(w http.ResponseWriter, r *http.Request) (string, bool) {
	p := r.PostFormValue("passphrase")
	if len(p) < codesign.MinPassphrase {
		s.flash(w, r, s.Tf(r, "La passphrase deve avere almeno %d caratteri.", codesign.MinPassphrase), "/agent-installer#signing")
		return "", false
	}
	if c := r.PostFormValue("passphrase2"); c != "" && c != p {
		s.flash(w, r, s.T(r, "Le due passphrase non coincidono."), "/agent-installer#signing")
		return "", false
	}
	return p, true
}

// consoleAdmin tells whether op manages console-wide settings, such as the
// signing key every tenant's installers are signed with: an Admin of one of
// the console's own directories, never through a federation link.
func (s *Server) consoleAdmin(op *Operator) bool {
	if op == nil || op.Federated || !hasRole(op, authn.RoleAdmin) {
		return false
	}
	dirs := s.consoleAdminDirs
	if len(dirs) == 0 {
		// One directory: it owns the console. Several: none until configured.
		tm := s.verifier.Config().TenantMap
		if len(tm) != 1 {
			return false
		}
		for tid := range tm {
			dirs = []string{tid}
		}
	}
	for _, d := range dirs {
		if d == op.TenantID {
			return true
		}
	}
	return false
}

// console requires a console administrator.
func (s *Server) console(h ctxHandler) http.Handler {
	return s.role(authn.RoleAdmin, func(w http.ResponseWriter, r *http.Request) {
		op := sessionFrom(r.Context()).data.Operator
		if !s.consoleAdmin(op) {
			s.log.Warn("forbidden: console-wide setting", "operator", op.Username, "path", r.URL.Path)
			http.Error(w, s.T(r, "permesso negato"), http.StatusForbidden)
			return
		}
		h(w, r)
	})
}

// signingDone audits a change of the console-wide signing material, in
// every tenant: it signs all of their installers.
func (s *Server) signingDone(w http.ResponseWriter, r *http.Request, action string, st *openrmmv1.BuilderStatus, msg string) {
	op := sessionFrom(r.Context()).data.Operator
	detail := map[string]any{}
	if ch, err := codesign.ParseChain([]byte(st.GetChainPem()), s.now()); err == nil {
		i := ch.LeafInfo()
		detail["subject"], detail["thumbprint"], detail["not_after"] = i.Subject, i.Thumbprint, i.NotAfter
	}
	s.auditAll(r.Context(), op, action, detail)
	s.flash(w, r, msg, "/agent-installer#signing")
}

// auditAll records a console-wide action in the log of every tenant.
func (s *Server) auditAll(ctx context.Context, op *Operator, action string, detail map[string]any) {
	tenants, err := s.store.ListTenants(ctx)
	if err != nil {
		s.log.Error("list tenants for audit", "err", err)
		return
	}
	for _, t := range tenants {
		s.audit(ctx, t.ID, op, action, "", detail)
	}
}

func (s *Server) builderCall(w http.ResponseWriter, r *http.Request, call func(context.Context) (*openrmmv1.BuilderStatus, error)) (*openrmmv1.BuilderStatus, bool) {
	if s.builder == nil {
		http.NotFound(w, r)
		return nil, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	st, err := call(ctx)
	if err != nil {
		s.flash(w, r, s.Tf(r, "Operazione non riuscita: %s", grpcMessage(err)), "/agent-installer#signing")
		return nil, false
	}
	return st, true
}

func (s *Server) handleCreateSigningCA(w http.ResponseWriter, r *http.Request) {
	pass, ok := s.passphrase(w, r)
	if !ok {
		return
	}
	st, ok := s.builderCall(w, r, func(ctx context.Context) (*openrmmv1.BuilderStatus, error) {
		return s.builder.CreateCA(ctx, &openrmmv1.CreateCARequest{Subject: subjectFrom(r), Passphrase: pass})
	})
	if ok {
		s.signingDone(w, r, "codesign.ca_created", st, s.T(r, "CA dedicata e certificato di firma creati."))
	}
}

func (s *Server) handleCreateSigningRequest(w http.ResponseWriter, r *http.Request) {
	pass, ok := s.passphrase(w, r)
	if !ok {
		return
	}
	st, ok := s.builderCall(w, r, func(ctx context.Context) (*openrmmv1.BuilderStatus, error) {
		return s.builder.CreateRequest(ctx, &openrmmv1.CreateRequestRequest{Subject: subjectFrom(r), Passphrase: pass})
	})
	if ok {
		s.auditAll(r.Context(), sessionFrom(r.Context()).data.Operator, "codesign.request_created", nil)
		s.flash(w, r, s.T(r, "Richiesta creata: scaricala e falla firmare dalla CA."), "/agent-installer#signing")
		_ = st
	}
}

func (s *Server) handleSigningRequestFile(w http.ResponseWriter, r *http.Request) {
	if s.builder == nil {
		http.NotFound(w, r)
		return
	}
	st, err := s.builder.Status(r.Context(), &openrmmv1.BuilderStatusRequest{})
	if err != nil || st.GetRequestPem() == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/pkcs10")
	w.Header().Set("Content-Disposition", `attachment; filename="codesign.csr"`)
	_, _ = io.WriteString(w, st.GetRequestPem())
}

func (s *Server) handleImportSigningCert(w http.ResponseWriter, r *http.Request) {
	st, ok := s.builderCall(w, r, func(ctx context.Context) (*openrmmv1.BuilderStatus, error) {
		return s.builder.ImportCertificate(ctx, &openrmmv1.ImportCertificateRequest{ChainPem: r.PostFormValue("certificate")})
	})
	if ok {
		s.signingDone(w, r, "codesign.certificate_imported", st, s.T(r, "Certificato di firma importato."))
	}
}

func (s *Server) handleImportSigningPFX(w http.ResponseWriter, r *http.Request) {
	pass, ok := s.passphrase(w, r)
	if !ok {
		return
	}
	f, _, err := r.FormFile("pfx")
	if err != nil {
		s.flash(w, r, s.T(r, "Scegli il file PFX."), "/agent-installer#signing")
		return
	}
	defer f.Close()
	pfx, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	st, ok := s.builderCall(w, r, func(ctx context.Context) (*openrmmv1.BuilderStatus, error) {
		return s.builder.ImportPFX(ctx, &openrmmv1.ImportPFXRequest{Pfx: pfx, PfxPassword: r.PostFormValue("pfx_password"), Passphrase: pass})
	})
	if ok {
		s.signingDone(w, r, "codesign.pfx_imported", st, s.T(r, "Certificato e chiave importati dal PFX."))
	}
}

func (s *Server) handleRenewSigning(w http.ResponseWriter, r *http.Request) {
	st, ok := s.builderCall(w, r, func(ctx context.Context) (*openrmmv1.BuilderStatus, error) {
		return s.builder.Renew(ctx, &openrmmv1.RenewRequest{Passphrase: r.PostFormValue("passphrase")})
	})
	if ok {
		s.signingDone(w, r, "codesign.renewed", st, s.T(r, "Certificato di firma rinnovato."))
	}
}

// ---- installers ----

// handleBuildInstaller starts the MFA approval of a build.
func (s *Server) handleBuildInstaller(w http.ResponseWriter, r *http.Request) {
	t, _ := tenantOf(r)
	version := r.PostFormValue("version")
	if s.builder == nil || len(s.installSettings(s.builderStatus(r.Context())).missing()) > 0 {
		s.flash(w, r, s.T(r, "La creazione degli installer non è configurata su questa console."), "/agent-installer")
		return
	}
	if _, err := s.store.GetRelease(r.Context(), version, installerPlatform); err != nil && version != s.unpublishedBundle(r.Context(), installerPlatform) {
		s.flash(w, r, s.T(r, "Versione non disponibile."), "/agent-installer")
		return
	}
	sess := sessionFrom(r.Context())
	sum := sha256.Sum256([]byte(t + "\x00" + version + "\x00" + ids.NewSecret(16)))
	p := &Pending{Purpose: "installer", State: ids.NewSecret(24), Nonce: "installer." + base64.RawURLEncoding.EncodeToString(sum[:]),
		CodeVerifier: oauth2.GenerateVerifier(), StartedAt: s.now(), Installer: version, Return: "/agent-installer"}
	sess.data.Pending = p
	if err := s.save(r.Context(), w, sess); err != nil {
		s.fail(w, r, err)
		return
	}
	s.redirectStepUp(w, r, sess, p)
}

// completeInstaller records the approval; the passphrase is asked next, so
// it never sits in the session.
func (s *Server) completeInstaller(w http.ResponseWriter, r *http.Request, sess *session, p *Pending, c *authn.Claims, v *authn.Verifier) {
	op, lang := sess.data.Operator, langOf(r, sess)
	if op == nil || c.ObjectID != op.ObjectID || c.TenantID != op.TenantID || c.Nonce != p.Nonce || !c.HasRole(authn.RoleAdmin) {
		http.Error(w, tr(lang, "l'approvazione deve essere fatta dallo stesso operatore"), http.StatusForbidden)
		return
	}
	if err := v.CheckFresh(c, s.now()); err != nil {
		http.Error(w, tr(lang, "accesso non valido o scaduto: riprova"), http.StatusForbidden)
		return
	}
	sess.data.InstallerApproval = &installerApproval{Version: p.Installer, At: s.now()}
	s.flashTo(w, r, sess, tr(lang, "Approvato: inserisci la passphrase della chiave di firma per creare l'installer."), "/agent-installer#build")
}

// handleConfirmInstaller builds the approved installer with the passphrase.
func (s *Server) handleConfirmInstaller(w http.ResponseWriter, r *http.Request) {
	t, _ := tenantOf(r)
	sess := sessionFrom(r.Context())
	op := sess.data.Operator
	a := sess.data.InstallerApproval
	sess.data.InstallerApproval = nil // one approval, one build
	if a == nil || s.now().Sub(a.At) > installerApprovalTTL {
		s.flash(w, r, s.T(r, "Approvazione scaduta: ricomincia."), "/agent-installer")
		return
	}
	if err := s.save(r.Context(), w, sess); err != nil {
		s.fail(w, r, err)
		return
	}
	extendDeadlines(w, 10*time.Minute)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	// The agent shipped with the console is published with its first
	// installer, signed with the same passphrase.
	if a.Version == s.unpublishedBundle(ctx, installerPlatform) {
		data, err := s.bundle.Files(installerPlatform)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		msg, err := s.publishRelease(r, op, a.Version, installerPlatform, "bundled with the console", data, r.PostFormValue("passphrase"))
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if msg != "" {
			s.flash(w, r, msg, "/agent-installer")
			return
		}
	}
	files := map[string][]byte{}
	for _, name := range []string{release.AgentFile("windows"), release.WatchdogFile("windows")} {
		b, err := s.store.GetReleaseFile(ctx, a.Version, installerPlatform, name)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		files[name] = b
	}
	// The token goes into the MSI: it never approves agents by itself.
	secret := ids.NewSecret(32)
	tok := store.EnrollmentToken{ID: ids.NewUUID(), TenantID: t, Description: "MSI " + a.Version + " " + s.now().Format("2006-01-02"),
		MaxUses: installerTokenUses, ExpiresAt: s.now().Add(installerTokenTTL)}
	ai := s.installSettings(s.builderStatus(ctx))
	req := &openrmmv1.BuildRequest{Version: a.Version, AgentExe: files[release.AgentFile("windows")],
		WatchdogExe: files[release.WatchdogFile("windows")], Passphrase: r.PostFormValue("passphrase"), TimestampUrl: ai.Timestamp,
		Properties: map[string]string{"SERVER": ai.Server, "ROOTCA": ai.RootCA, "ENROLLTOKEN": secret,
			"JOBSIGNINGKEYS": ai.JobKeys, "MODULESIGNINGKEYS": ai.ModuleKeys, "RELEASESIGNINGKEYS": ai.ReleaseKeys}}
	stream, err := s.builder.Build(ctx, req, grpc.MaxCallSendMsgSize(256<<20))
	if err != nil {
		s.flash(w, r, s.Tf(r, "Creazione non riuscita: %s", grpcMessage(err)), "/agent-installer")
		return
	}
	pr, pw := io.Pipe()
	var sum string
	go func() {
		for {
			c, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				_ = pw.Close()
				return
			}
			if err != nil {
				pw.CloseWithError(err)
				return
			}
			if c.GetSha256() != "" {
				sum = c.GetSha256()
			}
			if _, err := pw.Write(c.GetData()); err != nil {
				return
			}
		}
	}()
	sha, size, err := s.packages.Save(pr, maxInstaller)
	if err != nil {
		s.flash(w, r, s.Tf(r, "Creazione non riuscita: %s", grpcMessage(err)), "/agent-installer")
		return
	}
	if sha != sum {
		s.fail(w, r, errors.New("installer checksum mismatch"))
		return
	}
	st, err := s.builder.Status(ctx, &openrmmv1.BuilderStatusRequest{})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	signer := ""
	if ch, err := codesign.ParseChain([]byte(st.GetChainPem()), s.now()); err == nil {
		signer = ch.Leaf.Subject.String()
	}
	if err := s.store.CreateEnrollmentToken(r.Context(), tok, store.HashToken(secret)); err != nil {
		s.fail(w, r, err)
		return
	}
	inst := store.Installer{TenantID: t, ID: ids.NewUUID(), Version: a.Version, SHA256: sha, Size: size, TokenID: tok.ID,
		Signer: signer, CreatedBy: "operator:" + op.Username}
	if err := s.store.AddInstaller(r.Context(), inst); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r.Context(), t, op, "installer.built", inst.ID, map[string]any{"version": a.Version, "sha256": sha,
		"token": tok.ID, "signer": signer, "server": ai.Server})
	s.flash(w, r, s.Tf(r, "Installer %s creato e firmato.", a.Version), "/agent-installer")
}

func (s *Server) handleDownloadInstaller(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	id := r.PathValue("id")
	if !ok || !ids.IsUUID(id) {
		http.NotFound(w, r)
		return
	}
	inst, err := s.store.GetInstaller(r.Context(), t, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	f, err := s.packages.Open(inst.SHA256)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	extendDeadlines(w, 30*time.Minute)
	w.Header().Set("Content-Type", "application/x-msi")
	w.Header().Set("Content-Length", strconv.FormatInt(inst.Size, 10))
	w.Header().Set("Content-Disposition", `attachment; filename="openrmm-agent-`+inst.Version+`.msi"`)
	if _, err := io.Copy(w, f); err != nil {
		s.log.Debug("send installer", "err", err)
	}
}
