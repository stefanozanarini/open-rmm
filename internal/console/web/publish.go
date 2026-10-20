package web

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/console/authn"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/modules"
	"github.com/stefanozanarini/open-rmm/internal/release"
	"github.com/stefanozanarini/open-rmm/internal/signing"
	"github.com/stefanozanarini/open-rmm/modules/sdk"
)

// Publishing modules and agent releases from the console. The builder holds
// the module and agent release keys, encrypted with the console's signing
// passphrase. A console administrator approves with MFA, then uploads the
// module (a zip of its folder) or the release executables together with the
// passphrase: the console packs the module, the builder signs the manifest,
// the console verifies the signature with the keys agents trust and
// publishes. Bundles signed offline are still published with openrmm-admin.

const (
	publishModulePath  = "/modules/publish/upload"
	publishReleasePath = "/updates/publish/upload"
	// publishApprovalTTL is how long an MFA approval waits for the upload.
	publishApprovalTTL = 10 * time.Minute
	maxModuleUpload    = modules.MaxArchiveSize + 1<<20
	maxReleaseUpload   = 2*release.MaxFileSize + 1<<20
)

// streamedUploads are the multipart forms read part by part, with their
// body limit: the CSRF token comes first, and nothing is buffered on disk
// (the console's file system is read-only).
var streamedUploads = map[string]int64{
	uploadPath:         maxPackageSize + 1<<20,
	publishModulePath:  maxModuleUpload,
	publishReleasePath: maxReleaseUpload,
}

// Platforms a release can be published for from the console.
var releasePlatforms = []string{"windows/amd64", "windows/arm64", "linux/amd64", "linux/arm64"}

// publishApproval is a console administrator's MFA approval to publish one
// module or release.
type publishApproval struct {
	Kind string    `json:"kind"` // module | release
	At   time.Time `json:"at"`
}

// publishView is what the Modules and Agent versions pages need to offer
// publishing.
type publishView struct {
	ConsoleAdmin bool
	BuilderUp    bool
	KeysReady    bool
	KeyID        string // of the builder's key for this kind
	Approved     bool
	Platforms    []string
	// Bundled: the agent version shipped with the console, not published yet.
	Bundled string
	// Modules shipped with the console, not published yet.
	Modules []BundledModule
}

// builderStatus asks the builder for its state; nil when it is not
// configured or does not answer.
func (s *Server) builderStatus(ctx context.Context) *openrmmv1.BuilderStatus {
	if s.builder == nil {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	st, err := s.builder.Status(cctx, &openrmmv1.BuilderStatusRequest{})
	if err != nil {
		s.log.Warn("builder unreachable", "err", err)
		return nil
	}
	return st
}

// joinKeys merges public key lists ("," separated), without duplicates.
func joinKeys(lists ...string) string {
	var out []string
	seen := map[string]bool{}
	for _, l := range lists {
		for _, k := range strings.Split(l, ",") {
			if k = strings.TrimSpace(k); k != "" && !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	return strings.Join(out, ",")
}

// installSettings completes the configured installer settings with the
// builder's release keys. Keys in .env are added to them: keys signed
// offline, or the previous key during a rotation.
func (s *Server) installSettings(st *openrmmv1.BuilderStatus) AgentInstall {
	a := s.agentInstall
	if st != nil {
		a.ModuleKeys = joinKeys(st.GetModuleKey(), a.ModuleKeys)
		a.ReleaseKeys = joinKeys(st.GetReleaseKey(), a.ReleaseKeys)
	}
	return a
}

// keyring builds the keyring agents use for domain from a key list.
func keyring(domain signing.Domain, keys string) (*signing.Keyring, error) {
	k := signing.NewKeyring()
	for _, s := range strings.Split(keys, ",") {
		if strings.TrimSpace(s) == "" {
			continue
		}
		pub, err := signing.ParsePublicKey(s)
		if err != nil {
			return nil, err
		}
		if _, err := k.Add(pub, domain); err != nil {
			return nil, err
		}
	}
	return k, nil
}

func keyIDOf(pub string) string {
	k, err := signing.ParsePublicKey(pub)
	if err != nil {
		return ""
	}
	return signing.KeyID(k)
}

func (s *Server) publishData(r *http.Request, kind string) publishView {
	sess := sessionFrom(r.Context())
	v := publishView{ConsoleAdmin: s.consoleAdmin(sess.data.Operator), Platforms: releasePlatforms}
	if !v.ConsoleAdmin {
		return v
	}
	if st := s.builderStatus(r.Context()); st != nil {
		v.BuilderUp = true
		pub := st.GetReleaseKey()
		if kind == modulesKind {
			pub = st.GetModuleKey()
		}
		v.KeysReady, v.KeyID = pub != "", keyIDOf(pub)
	}
	if a := sess.data.PublishApproval; a != nil && a.Kind == kind && s.now().Sub(a.At) < publishApprovalTTL {
		v.Approved = true
	}
	if kind == releasesKind {
		v.Bundled = s.unpublishedBundle(r.Context(), installerPlatform)
	} else {
		v.Modules = s.unpublishedModules(r.Context())
	}
	return v
}

const (
	modulesKind  = "module"
	releasesKind = "release"
)

func publishReturn(kind string) string {
	if kind == modulesKind {
		return "/modules"
	}
	return "/updates"
}

// ---- release keys ----

func (s *Server) handleCreateReleaseKeys(w http.ResponseWriter, r *http.Request) {
	pass, ok := s.passphrase(w, r)
	if !ok {
		return
	}
	st, ok := s.builderCall(w, r, func(ctx context.Context) (*openrmmv1.BuilderStatus, error) {
		return s.builder.CreateReleaseKeys(ctx, &openrmmv1.CreateReleaseKeysRequest{Passphrase: pass})
	})
	if !ok {
		return
	}
	s.auditAll(r.Context(), sessionFrom(r.Context()).data.Operator, "release_keys.created", map[string]any{
		"module_key": st.GetModuleKey(), "release_key": st.GetReleaseKey()})
	s.flash(w, r, s.T(r, "Chiavi di moduli e release create. I prossimi installer le includono già."), "/agent-installer#release-keys")
}

// ---- approval ----

func (s *Server) startPublish(kind string) ctxHandler {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := sessionFrom(r.Context())
		p := &Pending{Purpose: "publish", State: ids.NewSecret(24), Nonce: "publish." + kind + "." + ids.NewSecret(16),
			CodeVerifier: oauth2.GenerateVerifier(), StartedAt: s.now(), Publish: kind, Return: publishReturn(kind)}
		sess.data.Pending = p
		if err := s.save(r.Context(), w, sess); err != nil {
			s.fail(w, r, err)
			return
		}
		s.redirectStepUp(w, r, sess, p)
	}
}

// completePublish records the approval; the upload and the passphrase come
// next, so neither sits in the session.
func (s *Server) completePublish(w http.ResponseWriter, r *http.Request, sess *session, p *Pending, c *authn.Claims, v *authn.Verifier) {
	op, lang := sess.data.Operator, langOf(r, sess)
	if op == nil || c.ObjectID != op.ObjectID || c.TenantID != op.TenantID || c.Nonce != p.Nonce || !c.HasRole(authn.RoleAdmin) ||
		!s.consoleAdmin(op) {
		http.Error(w, tr(lang, "l'approvazione deve essere fatta dallo stesso operatore"), http.StatusForbidden)
		return
	}
	if err := v.CheckFresh(c, s.now()); err != nil {
		http.Error(w, tr(lang, "accesso non valido o scaduto: riprova"), http.StatusForbidden)
		return
	}
	sess.data.PublishApproval = &publishApproval{Kind: p.Publish, At: s.now()}
	s.flashTo(w, r, sess, tr(lang, "Approvato: carica i file e inserisci la passphrase delle chiavi di firma."), publishReturn(p.Publish)+"#publish")
}

// approved tells whether the session holds a valid approval for kind.
func (s *Server) approved(sess *session, kind string) bool {
	a := sess.data.PublishApproval
	return a != nil && a.Kind == kind && s.now().Sub(a.At) < publishApprovalTTL
}

// consume ends the approval after a publication: one approval, one
// publication. A failed attempt keeps it, until it expires.
func (s *Server) consume(ctx context.Context, w http.ResponseWriter, sess *session) {
	sess.data.PublishApproval = nil
	if err := s.save(ctx, w, sess); err != nil {
		s.log.Error("save session", "err", err)
	}
}

// ---- uploads ----

// readUpload reads a streamed multipart form: the CSRF token first, then
// fields (at most 4 KB each) and the files named in files, each bounded by
// its limit.
func (s *Server) readUpload(w http.ResponseWriter, r *http.Request, files map[string]int64, back string) (map[string]string, map[string][]byte, bool) {
	sess := sessionFrom(r.Context())
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, s.T(r, "richiesta non valida"), http.StatusBadRequest)
		return nil, nil, false
	}
	fields, data := map[string]string{}, map[string][]byte{}
	csrfOK := false
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			http.Error(w, s.T(r, "richiesta non valida"), http.StatusBadRequest)
			return nil, nil, false
		}
		name := part.FormName()
		if !csrfOK {
			if name != "csrf" || !validCSRF(sess, readSmall(part)) {
				http.Error(w, s.T(r, "richiesta non valida"), http.StatusForbidden)
				return nil, nil, false
			}
			csrfOK = true
			continue
		}
		limit, isFile := files[name]
		if !isFile {
			fields[name] = readSmall(part)
			continue
		}
		b, err := io.ReadAll(io.LimitReader(part, limit+1))
		if err != nil {
			http.Error(w, s.T(r, "richiesta non valida"), http.StatusBadRequest)
			return nil, nil, false
		}
		if int64(len(b)) > limit {
			s.flash(w, r, s.T(r, "File troppo grande."), back)
			return nil, nil, false
		}
		data[name] = b
	}
	if !csrfOK {
		http.Error(w, s.T(r, "richiesta non valida"), http.StatusForbidden)
		return nil, nil, false
	}
	return fields, data, true
}

func readSmall(p *multipart.Part) string {
	b, _ := io.ReadAll(io.LimitReader(p, 4096))
	return string(b)
}

// signManifest has the builder sign raw, and maps its errors to messages.
func (s *Server) signManifest(ctx context.Context, r *http.Request, kind string, raw []byte, pass string) (*openrmmv1.SignManifestResponse, string) {
	if s.builder == nil {
		return nil, s.T(r, "Il servizio di firma non è configurato.")
	}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	res, err := s.builder.SignManifest(cctx, &openrmmv1.SignManifestRequest{Kind: kind, Manifest: raw, Passphrase: pass})
	switch status.Code(err) {
	case codes.OK:
		return res, ""
	case codes.PermissionDenied:
		return nil, s.T(r, "Passphrase errata.")
	case codes.FailedPrecondition:
		return nil, s.T(r, "Le chiavi di moduli e release non sono state create (pagina Installer).")
	default:
		return nil, s.Tf(r, "Firma non riuscita: %s", grpcMessage(err))
	}
}

func (s *Server) handlePublishModule(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	op := sess.data.Operator
	back := "/modules#publish"
	if !s.approved(sess, modulesKind) {
		s.flash(w, r, s.T(r, "Approvazione scaduta: ricomincia."), "/modules")
		return
	}
	extendDeadlines(w, 10*time.Minute)
	fields, files, ok := s.readUpload(w, r, map[string]int64{"module": maxModuleUpload}, back)
	if !ok {
		return
	}
	fail := func(msg string) { s.flash(w, r, msg, back) }
	zr, err := zip.NewReader(bytes.NewReader(files["module"]), int64(len(files["module"])))
	if err != nil {
		fail(s.T(r, "Il file deve essere uno zip della cartella del modulo."))
		return
	}
	src, err := modules.SourceRoot(zr)
	if err != nil {
		fail(s.T(r, "Nello zip manca manifest.json."))
		return
	}
	m, err := modules.ReadSource(src)
	if err != nil {
		fail(s.Tf(r, "Modulo non valido: %s", err.Error()))
		return
	}
	if msg, err := s.publishModule(r, op, m, src, fields["passphrase"]); err != nil {
		s.fail(w, r, err)
		return
	} else if msg != "" {
		fail(msg)
		return
	}
	s.consume(r.Context(), w, sess)
	s.flash(w, r, s.Tf(r, "Modulo %s %s firmato e pubblicato.", m.ID, m.Version), "/modules")
}

// handlePublishBundledModules publishes the selected modules shipped with
// the console, all with one approval and the passphrase.
func (s *Server) handlePublishBundledModules(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	op := sess.data.Operator
	back := "/modules#publish"
	if !s.approved(sess, modulesKind) {
		s.flash(w, r, s.T(r, "Approvazione scaduta: ricomincia."), "/modules")
		return
	}
	extendDeadlines(w, 10*time.Minute)
	bundled, err := s.modules.List()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = r.ParseForm()
	want := map[string]bool{}
	for _, k := range r.PostForm["module"] {
		want[k] = true
	}
	var done []string
	for _, b := range bundled {
		if !want[b.Key()] {
			continue
		}
		msg, err := s.publishModule(r, op, b.Manifest, os.DirFS(b.Dir), r.PostFormValue("passphrase"))
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if msg != "" {
			if len(done) > 0 {
				s.consume(r.Context(), w, sess)
				msg = s.Tf(r, "Pubblicati: %s. Poi: %s", strings.Join(done, ", "), msg)
			}
			s.flash(w, r, msg, back)
			return
		}
		done = append(done, b.Manifest.ID+" "+b.Manifest.Version)
	}
	if len(done) == 0 {
		s.flash(w, r, s.T(r, "Seleziona almeno un modulo."), back)
		return
	}
	s.consume(r.Context(), w, sess)
	s.flash(w, r, s.Tf(r, "Moduli firmati e pubblicati: %s.", strings.Join(done, ", ")), "/modules")
}

// publishModule packs a module source tree, has its manifest signed by the
// builder, verifies it with the keys agents trust and publishes it. msg is
// for the operator; err is an internal failure.
func (s *Server) publishModule(r *http.Request, op *Operator, m *modules.Manifest, src fs.FS, pass string) (msg string, err error) {
	ctx := r.Context()
	if _, err := s.store.GetModule(ctx, m.ID, m.Version); err == nil {
		return s.Tf(r, "%s %s è già pubblicato: aumenta la versione nel manifest.", m.ID, m.Version), nil
	}
	extra, err := modules.SDKFiles(m, sdk.FS)
	if err != nil {
		return "", err
	}
	archive, err := modules.PackFS(m, src, extra)
	if err != nil {
		return s.Tf(r, "Modulo non valido: %s", err.Error()), nil
	}
	raw, err := modules.SigningManifest(m)
	if err != nil {
		return "", err
	}
	res, msg := s.signManifest(ctx, r, modulesKind, raw, pass)
	if res == nil {
		return msg, nil
	}
	// Verified with the keys installers give agents, exactly as they will.
	keys, err := keyring(signing.DomainModuleManifest, s.installSettings(s.builderStatus(ctx)).ModuleKeys)
	if err != nil {
		return "", err
	}
	b := modules.Bundle{KeyID: res.GetKeyId(), Manifest: raw, Signature: res.GetSignature(), Archive: archive}
	v, err := b.Verify(keys)
	if err != nil {
		return "", err
	}
	err = s.store.PutModule(ctx, store.Module{ID: m.ID, Version: m.Version, Description: m.Description,
		KeyID: b.KeyID, Manifest: raw, Signature: b.Signature, ManifestSHA256: v.ManifestHash, Archive: archive,
		UploadedBy: "operator:" + op.Username})
	if errors.Is(err, store.ErrModuleExists) {
		return s.Tf(r, "%s %s è già pubblicato: aumenta la versione nel manifest.", m.ID, m.Version), nil
	}
	if err != nil {
		return "", err
	}
	s.auditAll(ctx, op, "module.published", map[string]any{"module": m.ID, "version": m.Version,
		"key_id": b.KeyID, "manifest_sha256": hex.EncodeToString(v.ManifestHash), "files": len(m.Files)})
	return "", nil
}

// ModuleBundle holds the modules shipped in the console image, one folder
// each (with manifest.json), as in the repository's modules/ directory.
type ModuleBundle struct{ Dir string }

// BundledModule is one module shipped with the console.
type BundledModule struct {
	Manifest *modules.Manifest
	Dir      string
}

// Key identifies the module version in forms.
func (b BundledModule) Key() string { return b.Manifest.ID + "@" + b.Manifest.Version }

// List returns the shipped modules, by id.
func (mb ModuleBundle) List() ([]BundledModule, error) {
	if mb.Dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(mb.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []BundledModule
	for _, e := range entries {
		dir := filepath.Join(mb.Dir, e.Name())
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, "manifest.json")); err != nil {
			continue // e.g. the SDK
		}
		m, err := modules.ReadSource(os.DirFS(dir))
		if err != nil {
			return nil, fmt.Errorf("bundled module %s: %w", e.Name(), err)
		}
		out = append(out, BundledModule{Manifest: m, Dir: dir})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Manifest.ID < out[j].Manifest.ID })
	return out, nil
}

// unpublishedModules returns the shipped modules whose version is not
// published yet.
func (s *Server) unpublishedModules(ctx context.Context) []BundledModule {
	list, err := s.modules.List()
	if err != nil {
		s.log.Error("bundled modules", "err", err)
		return nil
	}
	var out []BundledModule
	for _, b := range list {
		if _, err := s.store.GetModule(ctx, b.Manifest.ID, b.Manifest.Version); errors.Is(err, store.ErrNotFound) {
			out = append(out, b)
		}
	}
	return out
}

func (s *Server) handlePublishRelease(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	op := sess.data.Operator
	back := "/updates#publish"
	if !s.approved(sess, releasesKind) {
		s.flash(w, r, s.T(r, "Approvazione scaduta: ricomincia."), "/updates")
		return
	}
	extendDeadlines(w, 20*time.Minute)
	fields, files, ok := s.readUpload(w, r, map[string]int64{"agent": release.MaxFileSize, "watchdog": release.MaxFileSize}, back)
	if !ok {
		return
	}
	version, platform, notes := strings.TrimSpace(fields["version"]), fields["platform"], strings.TrimSpace(fields["notes"])
	var data map[string][]byte
	if fields["bundled"] != "" {
		// The agent shipped with the console: nothing to upload.
		version, platform, notes = s.unpublishedBundle(r.Context(), installerPlatform), installerPlatform, "bundled with the console"
		if version == "" {
			s.flash(w, r, s.T(r, "La versione inclusa nella console è già pubblicata."), back)
			return
		}
		var err error
		if data, err = s.bundle.Files(platform); err != nil {
			s.fail(w, r, err)
			return
		}
	} else {
		goos, _, _ := strings.Cut(platform, "/")
		data = map[string][]byte{release.AgentFile(goos): files["agent"], release.WatchdogFile(goos): files["watchdog"]}
	}
	msg, err := s.publishRelease(r, op, version, platform, notes, data, fields["passphrase"])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if msg != "" {
		s.flash(w, r, msg, back)
		return
	}
	s.consume(r.Context(), w, sess)
	s.flash(w, r, s.Tf(r, "Release %s per %s firmata e pubblicata.", version, platform), "/updates")
}

// AgentBundle is the agent shipped in the console image: Dir holds VERSION
// and one <os>-<arch> folder per platform with the executables. The console
// signs and publishes it as a release when an Admin first builds an
// installer for it, or from the Agent versions page.
type AgentBundle struct{ Dir string }

// Version is the bundled version, "" when there is none.
func (b AgentBundle) Version() string {
	if b.Dir == "" {
		return ""
	}
	raw, err := os.ReadFile(filepath.Join(b.Dir, "VERSION"))
	if err != nil {
		return ""
	}
	v := strings.TrimSpace(string(raw))
	if _, err := release.ParseVersion(v); err != nil {
		return ""
	}
	return v
}

// Files returns the bundled executables for platform, by release file name.
func (b AgentBundle) Files(platform string) (map[string][]byte, error) {
	goos, _, _ := strings.Cut(platform, "/")
	dir := filepath.Join(b.Dir, strings.ReplaceAll(platform, "/", "-"))
	out := map[string][]byte{}
	for _, name := range []string{release.AgentFile(goos), release.WatchdogFile(goos)} {
		data, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- fixed names in the image
		if err != nil {
			return nil, err
		}
		out[name] = data
	}
	return out, nil
}

// unpublishedBundle returns the bundled version when it is not published
// yet for platform.
func (s *Server) unpublishedBundle(ctx context.Context, platform string) string {
	v := s.bundle.Version()
	if v == "" {
		return ""
	}
	if _, err := s.store.GetRelease(ctx, v, platform); err == nil {
		return ""
	}
	if _, err := s.bundle.Files(platform); err != nil {
		return ""
	}
	return v
}

// publishRelease signs a release with the builder's key, verifies it with
// the keys agents trust and stores it. msg is for the operator; err is an
// internal failure.
func (s *Server) publishRelease(r *http.Request, op *Operator, version, platform, notes string, data map[string][]byte, pass string) (msg string, err error) {
	ctx := r.Context()
	m := &release.Manifest{Version: version, Platform: platform, ReleasedAt: s.now().UTC(), Notes: notes}
	for name, b := range data {
		if len(b) == 0 {
			return s.T(r, "Carica sia l'agente sia il watchdog."), nil
		}
		m.Files = append(m.Files, release.HashFile(name, b))
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Name < m.Files[j].Name })
	if err := m.Validate(); err != nil {
		return s.Tf(r, "Release non valida: %s", err.Error()), nil
	}
	if _, err := s.store.GetRelease(ctx, version, platform); err == nil {
		return s.Tf(r, "La release %s per %s è già pubblicata.", version, platform), nil
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	res, msg := s.signManifest(ctx, r, releasesKind, raw, pass)
	if res == nil {
		return msg, nil
	}
	keys, err := keyring(signing.DomainAgentRelease, s.installSettings(s.builderStatus(ctx)).ReleaseKeys)
	if err != nil {
		return "", err
	}
	if _, err := release.Verify(keys, res.GetKeyId(), raw, res.GetSignature()); err != nil {
		return "", err
	}
	err = s.store.PutRelease(ctx, store.Release{Version: version, Platform: platform, KeyID: res.GetKeyId(),
		Manifest: raw, Signature: res.GetSignature(), Notes: m.Notes, PublishedBy: "operator:" + op.Username, Files: data})
	if errors.Is(err, store.ErrReleaseExists) {
		return s.Tf(r, "La release %s per %s è già pubblicata.", version, platform), nil
	}
	if err != nil {
		return "", err
	}
	detail := map[string]any{"version": version, "platform": platform, "key_id": res.GetKeyId()}
	for _, f := range m.Files {
		detail[f.Name] = f.SHA256
	}
	s.auditAll(ctx, op, "release.published", detail)
	return "", nil
}
