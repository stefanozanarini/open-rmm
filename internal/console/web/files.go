package web

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	openrmmv1 "github.com/stefanozanarini/tempra-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/tempra-rmm/internal/console/jobreq"
	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/console/vuln"
	"github.com/stefanozanarini/tempra-rmm/internal/filesession"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
	"github.com/stefanozanarini/tempra-rmm/internal/modules"
)

// File sessions: one MFA approval opens a session on one or more agents for
// a limited time; the operator browses folders, downloads files (one, or the
// same path from every agent as a zip) and uploads files (to the same folder
// on every agent). The agent serves them itself (internal/filesession) and
// keeps its own folders out of reach. Every download, upload and new folder
// is in the audit log.

const (
	filesModule = "files"
	// filesPickup is how long the agents have to start an approved session.
	filesPickup        = 10 * time.Minute
	defaultFileMaxMB   = 1024
	maxFileMaxMB       = 16384
	filesUploadPath    = "/files/upload"
	maxFilesPerSession = 50
)

// minFilesAgent is the first agent version that serves file sessions.
const minFilesAgent = "1.1.0"

// filesAgent tells whether an agent version serves file sessions.
func filesAgent(version string) bool {
	return version != "" && vuln.CompareVersions(version, minFilesAgent) >= 0
}

func init() {
	streamedUploads[filesUploadPath] = maxFileMaxMB<<20 + 1<<20
}

// fileMaxBytes is the tenant's limit per transferred file.
func fileMaxBytes(st store.Settings) int64 {
	mb := st.FileMaxMB
	if mb <= 0 {
		mb = defaultFileMaxMB
	}
	return int64(min(mb, maxFileMaxMB)) << 20
}

// isFileModule tells whether a module version opens file sessions.
func (s *Server) isFileModule(ctx context.Context, id, version string) bool {
	m, err := s.store.GetModule(ctx, id, version)
	if err != nil {
		return false
	}
	man, err := modules.ParseManifest(m.Manifest)
	return err == nil && man.HasCapability(modules.CapFileSession)
}

// fileModule returns the newest files module.
func (s *Server) fileModule(r *http.Request) (store.Module, *modules.Manifest, bool) {
	latest, err := s.latestModules(r)
	if err != nil {
		return store.Module{}, nil, false
	}
	m, err := s.store.GetModule(r.Context(), filesModule, latest[filesModule])
	if err != nil {
		return store.Module{}, nil, false
	}
	man, err := modules.ParseManifest(m.Manifest)
	if err != nil || !man.HasCapability(modules.CapFileSession) {
		return store.Module{}, nil, false
	}
	return m, man, true
}

// handleOpenFiles asks the approval of a file session on the agent of the
// path, or on the agents of the form (agent=…).
func (s *Server) handleOpenFiles(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	agents := r.PostForm["agent"]
	back := "/agents"
	if id := r.PathValue("id"); id != "" {
		agents, back = []string{id}, "/agents/"+id
	}
	if len(agents) == 0 || len(agents) > maxFilesPerSession {
		s.flash(w, r, s.Tf(r, "Seleziona da 1 a %d computer.", maxFilesPerSession), back)
		return
	}
	mod, man, ok := s.fileModule(r)
	if !ok || s.shell == nil {
		s.flash(w, r, s.T(r, "La gestione dei file non è disponibile su questa console: pubblica il modulo files."), back)
		return
	}
	seen := map[string]bool{}
	var targets []string
	for _, id := range agents {
		if !ids.IsUUID(id) || seen[id] {
			continue
		}
		seen[id] = true
		a, err := s.store.GetAgent(r.Context(), t, id)
		if err != nil || a.Status != store.AgentActive {
			s.flash(w, r, s.T(r, "Solo gli agenti approvati possono ricevere comandi."), back)
			return
		}
		if _, ok := man.Entrypoints[a.Host.OS+"/"+a.Host.Arch]; !ok {
			s.flash(w, r, s.Tf(r, "Il modulo %s non supporta %s.", mod.ID, a.Host.Hostname), back)
			return
		}
		if !filesAgent(a.Host.AgentVersion) {
			s.flash(w, r, s.Tf(r, "%s ha l'agente %s: la gestione dei file richiede la versione %s o successiva. Pubblica la release dalla pagina Installer e attendi l'aggiornamento.",
				a.Host.Hostname, a.Host.AgentVersion, minFilesAgent), back)
			return
		}
		targets = append(targets, id)
	}
	set, err := s.store.GetSettings(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	minutes, err := strconv.Atoi(r.PostFormValue("minutes"))
	if err != nil || minutes < 5 || minutes > 240 {
		minutes = 60
	}
	params, _ := json.Marshal(map[string]int64{"minutes": int64(minutes), "max_bytes": fileMaxBytes(set)})
	req := &openrmmv1.JobRequest{TenantId: t, Module: mod.ID, ModuleVersion: mod.Version, ModuleSha256: mod.ManifestSHA256,
		Action: "open", ParamsJson: params, TtlSeconds: int64(filesPickup / time.Second), RequestNonce: jobreq.NewRequestNonce()}
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

// filesURL is the page of the sessions just approved.
func filesURL(jobs []string) string {
	q := url.Values{}
	for _, j := range jobs {
		q.Add("job", j)
	}
	return "/files?" + q.Encode()
}

// fileJob returns a file session job the operator approved.
func (s *Server) fileJob(r *http.Request, id string) (store.Job, store.Agent, bool) {
	t, ok := tenantOf(r)
	if !ok || !ids.IsUUID(id) {
		return store.Job{}, store.Agent{}, false
	}
	j, err := s.store.GetJob(r.Context(), t, id)
	op := sessionFrom(r.Context()).data.Operator
	// Only the operator who approved the session may use it.
	if err != nil || j.CreatedBy != "operator:"+op.Username || !s.isFileModule(r.Context(), j.Module, j.ModuleVersion) {
		return store.Job{}, store.Agent{}, false
	}
	a, err := s.store.GetAgent(r.Context(), t, j.AgentID)
	if err != nil {
		return store.Job{}, store.Agent{}, false
	}
	return j, a, true
}

// fileHub keeps one connection per open session, shared by the requests.
type fileHub struct {
	mu    sync.Mutex
	conns map[string]*fileConn
}

type fileConn struct {
	c      *filesession.Client
	cancel context.CancelFunc
}

var errWaiting = errors.New("waiting for the agent")

// fileClient returns the connection to a session, attaching to it.
func (s *Server) fileClient(r *http.Request, j store.Job) (*filesession.Client, error) {
	cur, err := s.store.GetJob(r.Context(), j.TenantID, j.ID)
	if err != nil {
		return nil, err
	}
	switch {
	case cur.State == store.JobExpired:
		return nil, errors.New(s.T(r, "Sessione scaduta: l'agente non si è collegato in tempo."))
	case cur.State == store.JobFailed || cur.State == store.JobRejected:
		return nil, errors.New(s.Tf(r, "Sessione rifiutata dall'agente: %s", cur.Error))
	case cur.State.Final():
		return nil, errors.New(s.T(r, "Sessione chiusa."))
	case cur.State != store.JobRunning:
		return nil, errWaiting
	}
	s.files.mu.Lock()
	defer s.files.mu.Unlock()
	if s.files.conns == nil {
		s.files.conns = map[string]*fileConn{}
	}
	if fc := s.files.conns[j.ID]; fc != nil {
		if fc.c.Err() == nil {
			return fc.c, nil
		}
		fc.cancel()
		delete(s.files.conns, j.ID)
	}
	if s.shell == nil {
		return nil, errors.New(s.T(r, "La sessione non è disponibile."))
	}
	ctx, cancel := context.WithCancel(context.Background())
	stream, err := s.shell.Attach(ctx)
	if err == nil {
		err = stream.Send(&openrmmv1.ShellFrame{TenantId: j.TenantID, JobId: j.ID})
	}
	if err != nil {
		cancel()
		return nil, errors.New(s.T(r, "La sessione non è disponibile."))
	}
	recv := func() ([]byte, error) {
		for {
			f, err := stream.Recv()
			if err != nil {
				return nil, err
			}
			if f.GetClose() {
				return nil, io.EOF
			}
			if len(f.GetData()) > 0 {
				return f.GetData(), nil
			}
		}
	}
	var sendMu sync.Mutex
	send := func(b []byte) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(&openrmmv1.ShellFrame{Data: b})
	}
	c := filesession.NewClient(recv, send)
	s.files.conns[j.ID] = &fileConn{c: c, cancel: cancel}
	return c, nil
}

func (s *Server) closeFileSession(id string) {
	s.files.mu.Lock()
	fc := s.files.conns[id]
	delete(s.files.conns, id)
	s.files.mu.Unlock()
	if fc != nil {
		fc.c.Close()
		fc.cancel()
	}
}

type filesData struct {
	Sessions []fileSessionView
	MaxBytes int64
	Max      string
}

type fileSessionView struct {
	Job   store.Job
	Agent store.Agent
}

func (s *Server) handleFilesPage(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	var d filesData
	for _, id := range r.URL.Query()["job"] {
		if j, a, ok := s.fileJob(r, id); ok {
			d.Sessions = append(d.Sessions, fileSessionView{Job: j, Agent: a})
		}
	}
	if len(d.Sessions) == 0 {
		http.NotFound(w, r)
		return
	}
	set, err := s.store.GetSettings(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d.MaxBytes = fileMaxBytes(set)
	d.Max = filesession.Bytes(d.MaxBytes)
	title := s.T(r, "File")
	if len(d.Sessions) == 1 {
		title = s.Tf(r, "File di %s", d.Sessions[0].Agent.Host.Hostname)
	}
	s.render(w, r, "files", title, d)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// fileError answers an API request that failed.
func (s *Server) fileError(w http.ResponseWriter, err error) {
	code := http.StatusBadGateway
	if errors.Is(err, errWaiting) {
		code = http.StatusConflict
	}
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

// handleFilesList returns a folder, or the drives when path is empty.
func (s *Server) handleFilesList(w http.ResponseWriter, r *http.Request) {
	j, _, ok := s.fileJob(r, r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	c, err := s.fileClient(r, j)
	if err != nil {
		s.fileError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	path := r.URL.Query().Get("path")
	if path == "" {
		roots, sep, err := c.Roots(ctx)
		if err != nil {
			s.fileError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"roots": roots, "sep": sep})
		return
	}
	m, err := c.List(ctx, path)
	if err != nil {
		s.fileError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"path": m.Path, "sep": m.Sep, "entries": m.Entries, "truncated": m.Truncated})
}

// handleFilesMkdir creates a folder.
func (s *Server) handleFilesMkdir(w http.ResponseWriter, r *http.Request) {
	j, a, ok := s.fileJob(r, r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	c, err := s.fileClient(r, j)
	if err != nil {
		s.fileError(w, err)
		return
	}
	path := r.PostFormValue("path")
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	if err := c.Mkdir(ctx, path); err != nil {
		s.fileError(w, err)
		return
	}
	s.audit(r.Context(), j.TenantID, sessionFrom(r.Context()).data.Operator, "files.mkdir", j.ID,
		map[string]any{"agent": a.ID, "hostname": a.Host.Hostname, "path": path})
	writeJSON(w, http.StatusOK, map[string]string{"path": path})
}

// baseName is the last element of an agent path (either separator).
func baseName(p string) string {
	p = strings.TrimRight(p, `/\`)
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		p = p[i+1:]
	}
	if p == "" || strings.HasSuffix(p, ":") {
		return "file"
	}
	return p
}

// handleFilesDownload streams one file of one agent.
func (s *Server) handleFilesDownload(w http.ResponseWriter, r *http.Request) {
	j, a, ok := s.fileJob(r, r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	c, err := s.fileClient(r, j)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	extendDeadlines(w, 4*time.Hour)
	path := r.URL.Query().Get("path")
	n, sum, err := c.Get(r.Context(), path, w, func(size int64) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": baseName(path)}))
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	})
	op := sessionFrom(r.Context()).data.Operator
	details := map[string]any{"agent": a.ID, "hostname": a.Host.Hostname, "path": path, "size": n, "sha256": sum}
	if err != nil {
		details["error"] = err.Error()
		if n == 0 && w.Header().Get("Content-Length") == "" {
			http.Error(w, err.Error(), http.StatusBadGateway)
		}
	}
	s.audit(context.WithoutCancel(r.Context()), j.TenantID, op, "files.download", j.ID, details)
}

// handleFilesZip streams the same path of every session as a zip, one
// folder per computer; a computer that fails adds an ERROR.txt.
func (s *Server) handleFilesZip(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	type target struct {
		j store.Job
		a store.Agent
	}
	var targets []target
	for _, id := range r.URL.Query()["job"] {
		if j, a, ok := s.fileJob(r, id); ok {
			targets = append(targets, target{j, a})
		}
	}
	if len(targets) == 0 || path == "" {
		http.NotFound(w, r)
		return
	}
	extendDeadlines(w, 4*time.Hour)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": baseName(path) + ".zip"}))
	zw := zip.NewWriter(w)
	op := sessionFrom(r.Context()).data.Operator
	for _, t := range targets {
		folder := strings.Map(func(r rune) rune {
			if strings.ContainsRune(`/\:*?"<>|`, r) {
				return '_'
			}
			return r
		}, t.a.Host.Hostname)
		details := map[string]any{"agent": t.a.ID, "hostname": t.a.Host.Hostname, "path": path, "zip": true}
		c, err := s.fileClient(r, t.j)
		if err == nil {
			var fw io.Writer
			fw, err = zw.CreateHeader(&zip.FileHeader{Name: folder + "/" + baseName(path), Method: zip.Deflate, Modified: time.Now()})
			if err == nil {
				var n int64
				var sum string
				n, sum, err = c.Get(r.Context(), path, fw, nil)
				details["size"], details["sha256"] = n, sum
			}
		}
		if err != nil {
			details["error"] = err.Error()
			if ew, zerr := zw.Create(folder + "/ERROR.txt"); zerr == nil {
				_, _ = io.WriteString(ew, err.Error()+"\n")
			}
		}
		s.audit(context.WithoutCancel(r.Context()), t.j.TenantID, op, "files.download", t.j.ID, details)
		if r.Context().Err() != nil {
			return
		}
	}
	_ = zw.Close()
}

// uploadResult is the outcome of an upload on one computer.
type uploadResult struct {
	Hostname string `json:"hostname"`
	Path     string `json:"path"`
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
}

// cleanFileName keeps the name of an uploaded file without any folder.
func cleanFileName(name string) (string, bool) {
	name = baseName(strings.TrimSpace(name))
	if name == "file" || name == "." || name == ".." || len(name) > 255 {
		return "", name == "file"
	}
	for _, r := range name {
		if r < 0x20 || strings.ContainsRune(`<>:"|?*`, r) {
			return "", false
		}
	}
	return name, true
}

// joinAgentPath appends a name to a folder of the agent, with the folder's
// separator.
func joinAgentPath(dir, name string) string {
	sep := "/"
	if strings.Contains(dir, `\`) || (len(dir) >= 2 && dir[1] == ':') {
		sep = `\`
	}
	return strings.TrimRight(dir, `/\`) + sep + name
}

// handleFilesUpload sends one file to the same folder of every session it
// names, read once from the request and passed to the agents together.
// Fields, in order: csrf, job (one or more), dir, size, overwrite, file.
func (s *Server) handleFilesUpload(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	sess := sessionFrom(r.Context())
	op := sess.data.Operator
	extendDeadlines(w, 4*time.Hour)
	mr, err := r.MultipartReader()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": s.T(r, "richiesta non valida")})
		return
	}
	readField := func(p *multipart.Part) string {
		b, _ := io.ReadAll(io.LimitReader(p, 4096))
		return strings.TrimSpace(string(b))
	}
	set, err := s.store.GetSettings(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	max := fileMaxBytes(set)
	csrfOK := false
	var jobs []string
	var dir string
	var size int64 = -1
	overwrite := false
	for {
		part, err := mr.NextPart()
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": s.T(r, "richiesta non valida")})
			return
		}
		name := part.FormName()
		if !csrfOK {
			if name != "csrf" || !validCSRF(sess, readField(part)) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": s.T(r, "richiesta non valida")})
				return
			}
			csrfOK = true
			continue
		}
		switch name {
		case "job":
			jobs = append(jobs, readField(part))
			continue
		case "dir":
			dir = readField(part)
			continue
		case "size":
			size, err = strconv.ParseInt(readField(part), 10, 64)
			if err != nil {
				size = -1
			}
			continue
		case "overwrite":
			overwrite = readField(part) == "1"
			continue
		case "file":
		default:
			continue
		}
		fileName, ok := cleanFileName(part.FileName())
		if !ok || dir == "" || len(jobs) == 0 || size < 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": s.T(r, "Nome del file o cartella non validi.")})
			return
		}
		if size > max {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": s.Tf(r, "Il file supera il limite di %s.", filesession.Bytes(max))})
			return
		}
		results := s.fanOutUpload(r, op, jobs, joinAgentPath(dir, fileName), size, overwrite, part)
		writeJSON(w, http.StatusOK, map[string]any{"results": results})
		return
	}
}

// fanOutUpload passes the file to every session at once: each agent reads
// from its own pipe; one that fails is dropped, the others go on.
func (s *Server) fanOutUpload(r *http.Request, op *Operator, jobs []string, path string, size int64, overwrite bool, src io.Reader) []uploadResult {
	type dest struct {
		j   store.Job
		a   store.Agent
		pw  *io.PipeWriter
		res uploadResult
		sum string
	}
	var dests []*dest
	var wg sync.WaitGroup
	for _, id := range jobs {
		j, a, ok := s.fileJob(r, id)
		if !ok {
			continue
		}
		d := &dest{j: j, a: a, res: uploadResult{Hostname: a.Host.Hostname, Path: path}}
		dests = append(dests, d)
		c, err := s.fileClient(r, j)
		if err != nil {
			d.res.Error = err.Error()
			continue
		}
		pr, pw := io.Pipe()
		d.pw = pw
		wg.Add(1)
		go func() {
			defer wg.Done()
			sum, err := c.Put(r.Context(), path, size, overwrite, pr)
			if err != nil {
				d.res.Error = err.Error()
				_ = pr.CloseWithError(err)
				return
			}
			d.res.OK, d.sum = true, sum
			_, _ = io.Copy(io.Discard, pr)
		}()
	}
	buf := make([]byte, filesession.ChunkSize)
	var read int64
	for read < size {
		n, err := src.Read(buf)
		for _, d := range dests {
			if d.pw == nil || n == 0 {
				continue
			}
			if _, werr := d.pw.Write(buf[:n]); werr != nil {
				d.pw = nil // that agent failed; its result says why
			}
		}
		read += int64(n)
		if err != nil {
			break
		}
	}
	for _, d := range dests {
		if d.pw != nil {
			if read < size {
				_ = d.pw.CloseWithError(errors.New(s.T(r, "caricamento interrotto")))
			} else {
				_ = d.pw.Close()
			}
		}
	}
	wg.Wait()
	out := make([]uploadResult, 0, len(dests))
	for _, d := range dests {
		details := map[string]any{"agent": d.a.ID, "hostname": d.a.Host.Hostname, "path": path, "size": size,
			"overwrite": overwrite, "sha256": d.sum}
		if d.res.Error != "" {
			details["error"] = d.res.Error
		}
		s.audit(context.WithoutCancel(r.Context()), d.j.TenantID, op, "files.upload", d.j.ID, details)
		out = append(out, d.res)
	}
	return out
}

// handleFilesClose ends the sessions of the form (job=…).
func (s *Server) handleFilesClose(w http.ResponseWriter, r *http.Request) {
	for _, id := range r.PostForm["job"] {
		if j, _, ok := s.fileJob(r, id); ok {
			if c, err := s.fileClient(r, j); err == nil {
				c.Close()
			}
			s.closeFileSession(j.ID)
		}
	}
	s.flash(w, r, s.T(r, "Sessione chiusa."), "/jobs")
}
