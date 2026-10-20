package web

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/console/jobreq"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/console/wingetcat"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/inventory"
	"github.com/stefanozanarini/open-rmm/internal/modules"
	"github.com/stefanozanarini/open-rmm/internal/pkgref"
)

const (
	uploadPath     = "/packages/upload"
	maxPackageSize = 2 << 30
	softwareModule = "software"
)

var (
	shaHexRe   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	guidRe     = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)
	versionTxt = regexp.MustCompile(`^[\pL\pN][\pL\pN ._+()-]{0,63}$`)
)

// outdatedAgent is an agent with an older version of a catalog application.
type outdatedAgent struct {
	AgentID, Hostname, Installed string
}

// catalogView is a catalog application with its fleet status.
type catalogView struct {
	store.CatalogApp
	Release   wingetcat.Release
	Package   *store.Package // the latest release in the library, if imported
	Installed int
	Outdated  []outdatedAgent
}

type packagesData struct {
	Packages []store.Package
	Catalog  []catalogView
	Kinds    []string
}

// catalogStatus matches the catalog against every inventory.
func (s *Server) catalogStatus(ctx context.Context, tenant string) ([]catalogView, error) {
	apps, err := s.store.ListCatalogApps(ctx, tenant)
	if err != nil || len(apps) == 0 {
		return nil, err
	}
	invs, err := s.store.ListInventories(ctx, tenant)
	if err != nil {
		return nil, err
	}
	agents, err := s.store.ListAgents(ctx, tenant)
	if err != nil {
		return nil, err
	}
	names := map[string]store.Agent{}
	for _, a := range agents {
		names[a.ID] = a
	}
	type parsed struct {
		agent store.Agent
		sw    []inventory.Software
	}
	var fleet []parsed
	for _, inv := range invs {
		a, ok := names[inv.AgentID]
		if !ok || a.Status != store.AgentActive {
			continue
		}
		p, err := inventory.Parse(inv.Data)
		if err != nil {
			continue
		}
		fleet = append(fleet, parsed{agent: a, sw: p.Software})
	}
	pkgs, err := s.store.ListPackages(ctx, tenant)
	if err != nil {
		return nil, err
	}
	var out []catalogView
	for _, app := range apps {
		v := catalogView{CatalogApp: app}
		_ = json.Unmarshal(app.Release, &v.Release)
		for i := range pkgs {
			if pkgs[i].SHA256 == v.Release.SHA256 {
				v.Package = &pkgs[i]
			}
		}
		for _, f := range fleet {
			versions := wingetcat.Installed(f.sw, app.MatchName, app.ProductCodes)
			if len(versions) == 0 {
				continue
			}
			v.Installed++
			for _, ver := range versions {
				if wingetcat.CompareVersions(ver, app.DisplayVersion) < 0 {
					v.Outdated = append(v.Outdated, outdatedAgent{AgentID: f.agent.ID, Hostname: f.agent.Host.Hostname, Installed: ver})
					break
				}
			}
		}
		sort.Slice(v.Outdated, func(i, j int) bool { return v.Outdated[i].Hostname < v.Outdated[j].Hostname })
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool { return len(out[i].Outdated) > len(out[j].Outdated) })
	return out, nil
}

func (s *Server) handlePackages(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	d := packagesData{Kinds: []string{store.KindMSI, store.KindExe, store.KindInno, store.KindNullsoft, store.KindBurn}}
	var err error
	if d.Packages, err = s.store.ListPackages(r.Context(), t); err != nil {
		s.fail(w, r, err)
		return
	}
	if d.Catalog, err = s.catalogStatus(r.Context(), t); err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, "packages", s.T(r, "Software"), d)
}

// handleUpload stores an uploaded installer. The CSRF token must be the
// first part, before the file.
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	sess := sessionFrom(r.Context())
	op := sess.data.Operator
	if s.packages.Path == "" {
		s.flash(w, r, s.T(r, "Archivio dei pacchetti non configurato (OPENRMM_PACKAGES_DIR)."), "/packages")
		return
	}
	extendDeadlines(w, time.Hour)
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, s.T(r, "richiesta non valida"), http.StatusBadRequest)
		return
	}
	readField := func(p *multipart.Part) string {
		b, _ := io.ReadAll(io.LimitReader(p, 4096))
		return strings.TrimSpace(string(b))
	}
	fields := map[string]string{}
	csrfOK := false
	var sha, fileName string
	var size int64
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			http.Error(w, s.T(r, "richiesta non valida"), http.StatusBadRequest)
			return
		}
		name := part.FormName()
		if !csrfOK {
			if name != "csrf" || !validCSRF(sess, readField(part)) {
				http.Error(w, s.T(r, "richiesta non valida"), http.StatusForbidden)
				return
			}
			csrfOK = true
			continue
		}
		if name == "file" {
			fileName = part.FileName()
			if i := strings.LastIndexAny(fileName, `/\`); i >= 0 {
				fileName = fileName[i+1:]
			}
			if sha, size, err = s.packages.Save(part, maxPackageSize); err != nil {
				s.log.Warn("package upload failed", "err", err)
				s.flash(w, r, s.Tf(r, "Caricamento non riuscito: %v", err), "/packages")
				return
			}
			continue
		}
		fields[name] = readField(part)
	}
	if !csrfOK {
		http.Error(w, s.T(r, "richiesta non valida"), http.StatusForbidden)
		return
	}
	if sha == "" {
		s.flash(w, r, s.T(r, "Seleziona il file da caricare."), "/packages")
		return
	}
	p := store.Package{TenantID: t, SHA256: sha, Name: fields["name"], Version: fields["version"], Publisher: fields["publisher"],
		FileName: fileName, Size: size, Kind: fields["kind"], SilentArgs: fields["silent_args"],
		ProductCode: strings.ToUpper(fields["product_code"]), AllowUnsigned: fields["allow_unsigned"] == "on",
		Source: "upload", CreatedBy: "operator:" + op.Username}
	if p.Kind == "" && strings.HasSuffix(strings.ToLower(fileName), ".msi") {
		p.Kind = store.KindMSI
	}
	if msg := validatePackage(s.lang(r), p); msg != "" {
		s.flash(w, r, msg, "/packages")
		return
	}
	s.addPackage(w, r, p)
}

// extendDeadlines lifts the server's read and write timeouts for a long
// request (uploads, downloads from the catalog).
func extendDeadlines(w http.ResponseWriter, d time.Duration) {
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(d))
	_ = rc.SetWriteDeadline(time.Now().Add(d))
}

func validatePackage(lang string, p store.Package) string {
	switch {
	case !versionTxt.MatchString(p.Name):
		return tr(lang, "Indica il nome del software.")
	case !versionTxt.MatchString(p.Version):
		return tr(lang, "Indica la versione.")
	case !pkgref.ValidFileName(p.FileName):
		return tr(lang, "Nome del file non valido: usa lettere, cifre, spazi e . _ - ( ) +")
	case !store.ValidKind(p.Kind):
		return tr(lang, "Tipo di installer non valido.")
	case p.Kind == store.KindExe && p.SilentArgs == "":
		return tr(lang, "Per un installer exe generico indica le opzioni di installazione silenziosa.")
	case p.ProductCode != "" && !guidRe.MatchString(p.ProductCode):
		return tr(lang, "Il codice prodotto deve essere un GUID tra parentesi graffe.")
	case len(p.SilentArgs) > 1000:
		return tr(lang, "Opzioni troppo lunghe.")
	}
	return ""
}

func (s *Server) addPackage(w http.ResponseWriter, r *http.Request, p store.Package) {
	op := sessionFrom(r.Context()).data.Operator
	switch err := s.store.PutPackage(r.Context(), p); {
	case errors.Is(err, store.ErrPackageExists):
		s.flash(w, r, s.T(r, "Questo file è già nella libreria."), "/packages")
		return
	case err != nil:
		s.fail(w, r, err)
		return
	}
	s.audit(r.Context(), p.TenantID, op, "package.added", p.SHA256, map[string]any{"name": p.Name, "version": p.Version,
		"file": p.FileName, "size": p.Size, "kind": p.Kind, "source": p.Source, "winget_id": p.WingetID, "url": p.SourceURL,
		"allow_unsigned": p.AllowUnsigned})
	s.flash(w, r, s.Tf(r, "%s %s aggiunto alla libreria.", p.Name, p.Version), "/packages")
}

func (s *Server) catalogApp(ctx context.Context, tenant, id, by string, keepMatch string) (store.CatalogApp, error) {
	rel, err := s.winget.Latest(ctx, id)
	if err != nil {
		return store.CatalogApp{}, err
	}
	raw, _ := json.Marshal(rel)
	app := store.CatalogApp{TenantID: tenant, WingetID: rel.ID, Name: rel.Name, Publisher: rel.Publisher, Version: rel.Version,
		DisplayVersion: rel.DisplayVersion, MatchName: rel.MatchName, ProductCodes: rel.ProductCodes, Release: raw,
		CheckedAt: s.now(), AddedBy: by}
	if keepMatch != "" {
		app.MatchName = keepMatch
	}
	return app, s.store.PutCatalogApp(ctx, app)
}

func (s *Server) handleAddCatalog(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	op := sessionFrom(r.Context()).data.Operator
	id := strings.TrimSpace(r.PostFormValue("winget_id"))
	if !wingetcat.IDRe.MatchString(id) {
		s.flash(w, r, s.T(r, "Id winget non valido (es. 7zip.7zip, Mozilla.Firefox)."), "/packages")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	app, err := s.catalogApp(ctx, t, id, "operator:"+op.Username, "")
	if err != nil {
		s.flash(w, r, s.Tf(r, "Impossibile leggere %s dal catalogo winget: %v", id, err), "/packages")
		return
	}
	s.audit(r.Context(), t, op, "catalog.added", id, map[string]any{"version": app.Version, "match_name": app.MatchName})
	// The installer comes along at once, so the application can be
	// distributed right away; a failed download leaves the catalog entry
	// with its Download button.
	if s.packages.Path != "" {
		var rel wingetcat.Release
		if err := json.Unmarshal(app.Release, &rel); err == nil {
			if _, err := s.store.GetPackage(r.Context(), t, rel.SHA256); errors.Is(err, store.ErrNotFound) {
				extendDeadlines(w, 35*time.Minute)
				dctx, dcancel := context.WithTimeout(r.Context(), 30*time.Minute)
				defer dcancel()
				size, err := s.winget.Download(dctx, &rel, s.packages, maxPackageSize)
				if err != nil {
					s.log.Warn("catalog download", "id", rel.ID, "url", rel.URL, "err", err)
					s.flash(w, r, s.Tf(r, "%s %s aggiunto al catalogo, ma il download non è riuscito: %v", app.Name, app.Version, err), "/packages")
					return
				}
				s.addPackage(w, r, store.Package{TenantID: t, SHA256: rel.SHA256, Name: rel.Name, Version: rel.Version,
					Publisher: rel.Publisher, FileName: rel.FileName, Size: size, Kind: rel.Kind, SilentArgs: rel.SilentArgs,
					ProductCode: rel.ProductCode, Source: "winget", WingetID: rel.ID, SourceURL: rel.URL, CreatedBy: "operator:" + op.Username})
				return
			}
		}
	}
	s.flash(w, r, s.Tf(r, "%s %s aggiunto al catalogo.", app.Name, app.Version), "/packages")
}

func (s *Server) handleRefreshCatalog(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	op := sessionFrom(r.Context()).data.Operator
	apps, err := s.store.ListCatalogApps(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	extendDeadlines(w, 6*time.Minute)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	var failed []string
	updated := 0
	for _, a := range apps {
		app, err := s.catalogApp(ctx, t, a.WingetID, a.AddedBy, a.MatchName)
		if err != nil {
			failed = append(failed, a.WingetID)
			s.log.Warn("catalog refresh", "id", a.WingetID, "err", err)
			continue
		}
		if app.Version != a.Version {
			updated++
		}
	}
	s.audit(r.Context(), t, op, "catalog.refreshed", t, map[string]any{"apps": len(apps), "new_versions": updated, "failed": failed})
	msg := s.Tf(r, "Catalogo aggiornato: %d nuove versioni.", updated)
	if len(failed) > 0 {
		msg += " " + s.Tf(r, "Non riuscito per: %s", strings.Join(failed, ", "))
	}
	s.flash(w, r, msg, "/packages")
}

func (s *Server) handleCatalogMatch(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	op := sessionFrom(r.Context()).data.Operator
	app, err := s.store.GetCatalogApp(r.Context(), t, r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if r.PostFormValue("delete") != "" {
		if err := s.store.DeleteCatalogApp(r.Context(), t, app.WingetID); err != nil {
			s.fail(w, r, err)
			return
		}
		s.audit(r.Context(), t, op, "catalog.removed", app.WingetID, nil)
		s.flash(w, r, s.Tf(r, "%s rimosso dal catalogo.", app.Name), "/packages")
		return
	}
	m := strings.TrimSpace(r.PostFormValue("match_name"))
	if len(m) < 2 || len(m) > 120 {
		s.flash(w, r, s.T(r, "Il nome per il riconoscimento deve avere da 2 a 120 caratteri."), "/packages")
		return
	}
	prev := app.MatchName
	app.MatchName = m
	if err := s.store.PutCatalogApp(r.Context(), app); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r.Context(), t, op, "catalog.match_changed", app.WingetID, map[string]any{"from": prev, "to": m})
	s.flash(w, r, s.Tf(r, "Riconoscimento di %s aggiornato.", app.Name), "/packages")
}

// handleImportCatalog downloads the latest installer of a catalog
// application into the library.
func (s *Server) handleImportCatalog(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	op := sessionFrom(r.Context()).data.Operator
	if s.packages.Path == "" {
		s.flash(w, r, s.T(r, "Archivio dei pacchetti non configurato (OPENRMM_PACKAGES_DIR)."), "/packages")
		return
	}
	app, err := s.store.GetCatalogApp(r.Context(), t, r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var rel wingetcat.Release
	if err := json.Unmarshal(app.Release, &rel); err != nil {
		s.fail(w, r, err)
		return
	}
	extendDeadlines(w, 35*time.Minute)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()
	size, err := s.winget.Download(ctx, &rel, s.packages, maxPackageSize)
	if err != nil {
		s.log.Warn("catalog download", "id", rel.ID, "url", rel.URL, "err", err)
		s.flash(w, r, s.Tf(r, "Download non riuscito: %v", err), "/packages")
		return
	}
	p := store.Package{TenantID: t, SHA256: rel.SHA256, Name: rel.Name, Version: rel.Version, Publisher: rel.Publisher,
		FileName: rel.FileName, Size: size, Kind: rel.Kind, SilentArgs: rel.SilentArgs, ProductCode: rel.ProductCode,
		Source: "winget", WingetID: rel.ID, SourceURL: rel.URL, CreatedBy: "operator:" + op.Username}
	s.addPackage(w, r, p)
}

// deployRow is an agent in the deployment form.
type deployRow struct {
	Agent     store.Agent
	Installed string
	Outdated  bool
	Checked   bool
}

type deployData struct {
	Package store.Package
	Rows    []deployRow
	Module  string
}

func (s *Server) softwareModule(ctx context.Context) (*modules.Manifest, store.Module, error) {
	mods, err := s.store.ListModules(ctx)
	if err != nil {
		return nil, store.Module{}, err
	}
	var best *modules.Manifest
	for _, m := range mods {
		if m.ID != softwareModule {
			continue
		}
		man, err := modules.ParseManifest(m.Manifest)
		if err != nil {
			continue
		}
		if best == nil || wingetcat.CompareVersions(man.Version, best.Version) > 0 {
			best = man
		}
	}
	if best == nil {
		return nil, store.Module{}, errors.New("publish the software module first")
	}
	full, err := s.store.GetModule(ctx, best.ID, best.Version)
	if err != nil {
		return nil, store.Module{}, err
	}
	return best, full, nil
}

func (s *Server) handleDeployForm(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	sha := r.PathValue("sha")
	if !ok || !shaHexRe.MatchString(sha) {
		http.NotFound(w, r)
		return
	}
	p, err := s.store.GetPackage(r.Context(), t, sha)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	d := deployData{Package: p}
	if man, _, err := s.softwareModule(r.Context()); err == nil {
		d.Module = man.Version
	}
	agents, err := s.store.ListAgents(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	installed := map[string]string{}
	var app *store.CatalogApp
	if p.WingetID != "" {
		if a, err := s.store.GetCatalogApp(r.Context(), t, p.WingetID); err == nil {
			app = &a
		}
	}
	if app != nil {
		invs, _ := s.store.ListInventories(r.Context(), t)
		for _, inv := range invs {
			if parsed, err := inventory.Parse(inv.Data); err == nil {
				if v := wingetcat.Installed(parsed.Software, app.MatchName, app.ProductCodes); len(v) > 0 {
					installed[inv.AgentID] = v[0]
				}
			}
		}
	}
	preset := map[string]bool{}
	for _, id := range r.URL.Query()["agent"] {
		preset[id] = true
	}
	for _, a := range agents {
		if a.Status != store.AgentActive || a.Host.OS != "windows" {
			continue
		}
		row := deployRow{Agent: a, Installed: installed[a.ID]}
		row.Outdated = row.Installed != "" && wingetcat.CompareVersions(row.Installed, p.Version) < 0
		row.Checked = row.Outdated
		if len(preset) > 0 {
			row.Checked = preset[a.ID]
		}
		d.Rows = append(d.Rows, row)
	}
	sort.SliceStable(d.Rows, func(i, j int) bool {
		if d.Rows[i].Checked != d.Rows[j].Checked {
			return d.Rows[i].Checked
		}
		return d.Rows[i].Agent.Host.Hostname < d.Rows[j].Agent.Host.Hostname
	})
	s.render(w, r, "deploy", s.Tf(r, "Distribuisci %s %s", p.Name, p.Version), d)
}

func ttlFrom(r *http.Request) int64 {
	ttlMin, err := strconv.Atoi(r.PostFormValue("ttl_minutes"))
	if err != nil || ttlMin < 5 || ttlMin > 24*60 {
		ttlMin = 60
	}
	return int64(ttlMin) * 60
}

func (s *Server) handleDeploy(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	sha := r.PathValue("sha")
	if !ok || !shaHexRe.MatchString(sha) {
		http.NotFound(w, r)
		return
	}
	back := "/packages/" + sha + "/deploy"
	p, err := s.store.GetPackage(r.Context(), t, sha)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	man, mod, err := s.softwareModule(r.Context())
	if err != nil {
		s.flash(w, r, s.T(r, "Pubblica prima il modulo software."), back)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, s.T(r, "richiesta non valida"), http.StatusBadRequest)
		return
	}
	var targets []string
	for _, id := range r.PostForm["agent"] {
		if !ids.IsUUID(id) {
			continue
		}
		a, err := s.store.GetAgent(r.Context(), t, id)
		if err != nil || a.Status != store.AgentActive {
			s.flash(w, r, s.T(r, "Solo gli agenti approvati possono ricevere comandi."), back)
			return
		}
		targets = append(targets, id)
	}
	if len(targets) == 0 || len(targets) > jobreq.MaxAgents {
		s.flash(w, r, s.Tf(r, "Seleziona da 1 a %d endpoint.", jobreq.MaxAgents), back)
		return
	}
	params := map[string]any{"kind": p.Kind, "allow_unsigned": p.AllowUnsigned}
	if p.Kind == store.KindMSI {
		params["msi_properties"] = p.SilentArgs
	} else if p.SilentArgs != "" {
		params["silent_args"] = p.SilentArgs
	}
	raw, _ := json.Marshal(params)
	shaBytes, _ := hex.DecodeString(p.SHA256)
	req := &openrmmv1.JobRequest{TenantId: t, Module: man.ID, ModuleVersion: man.Version, ModuleSha256: mod.ManifestSHA256,
		Action: "install", ParamsJson: raw, TtlSeconds: ttlFrom(r), RequestNonce: jobreq.NewRequestNonce(),
		Packages: []*openrmmv1.PackageRef{{Sha256: shaBytes, FileName: p.FileName, Size: p.Size}}}
	if len(targets) == 1 {
		req.AgentId = targets[0]
	} else {
		req.AgentIds = targets
	}
	if err := jobreq.Validate(req); err != nil {
		s.flash(w, r, s.Tf(r, "Richiesta non valida: %v", err), back)
		return
	}
	s.startStepUp(w, r, sessionFrom(r.Context()), req, back)
}

// handleUninstall starts the approval of an uninstall job.
func (s *Server) handleUninstall(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	id := r.PathValue("id")
	if !ok || !ids.IsUUID(id) {
		http.NotFound(w, r)
		return
	}
	back := "/agents/" + id
	a, err := s.store.GetAgent(r.Context(), t, id)
	if err != nil || a.Status != store.AgentActive {
		s.flash(w, r, s.T(r, "Solo gli agenti approvati possono ricevere comandi."), back)
		return
	}
	man, mod, err := s.softwareModule(r.Context())
	if err != nil {
		s.flash(w, r, s.T(r, "Pubblica prima il modulo software."), back)
		return
	}
	name, version, code := strings.TrimSpace(r.PostFormValue("name")), strings.TrimSpace(r.PostFormValue("version")),
		strings.ToUpper(strings.TrimSpace(r.PostFormValue("product_code")))
	params := map[string]any{}
	switch {
	case code != "" && guidRe.MatchString(code):
		params["product_code"] = code
	case name != "" && len(name) <= 512:
		params["name"] = name
		if version != "" {
			params["version"] = version
		}
	default:
		s.flash(w, r, s.T(r, "Applicazione non valida."), back)
		return
	}
	if strings.HasPrefix(strings.ToLower(name), "open-rmm") {
		s.flash(w, r, s.T(r, "L'agente open-rmm non si disinstalla dalla console."), back)
		return
	}
	if extra := strings.TrimSpace(r.PostFormValue("uninstall_args")); extra != "" {
		params["uninstall_args"] = extra
	}
	raw, _ := json.Marshal(params)
	req := &openrmmv1.JobRequest{TenantId: t, AgentId: id, Module: man.ID, ModuleVersion: man.Version,
		ModuleSha256: mod.ManifestSHA256, Action: "uninstall", ParamsJson: raw, TtlSeconds: ttlFrom(r),
		RequestNonce: jobreq.NewRequestNonce()}
	if err := jobreq.Validate(req); err != nil {
		s.flash(w, r, s.Tf(r, "Richiesta non valida: %v", err), back)
		return
	}
	s.startStepUp(w, r, sessionFrom(r.Context()), req, back)
}
