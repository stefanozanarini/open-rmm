package web

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	openrmmv1 "github.com/stefanozanarini/tempra-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/tempra-rmm/internal/console/jobreq"
	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
	"github.com/stefanozanarini/tempra-rmm/internal/workflow"
)

// Software distribution workflows (internal/workflow): a catalog with the
// deployment status of each, an editor where every save is a new revision,
// and runs from the bulk actions, signed like any job after MFA.

// Labels of the step and rule types in the editor.
var (
	wfStepLabels = map[string]string{workflow.StepScript: "Esegui uno script", workflow.StepCommand: "Esegui un comando",
		workflow.StepDownload: "Scarica un file", workflow.StepHTTP: "Chiamata HTTP", workflow.StepInstall: "Installa"}
	wfRuleLabels = map[string]string{workflow.RuleApp: "Applicazione installata", workflow.RuleRegistry: "Registro",
		workflow.RuleFile: "File o cartella", workflow.RuleScript: "Script PowerShell",
		workflow.RuleUserGroup: "Utente nel gruppo AD", workflow.RuleComputerGroup: "Computer nel gruppo AD"}
)

// maxWorkflowJobs bounds the jobs read for the deployment status.
const maxWorkflowJobs = 5000

// Deployment states of a workflow on a computer, from its latest job.
const (
	wfOK        = "ok"        // the steps ran and the detection held
	wfCompliant = "compliant" // already compliant, nothing ran
	wfRunning   = "running"
	wfFailed    = "failed"
)

// wfRun is the latest run of a workflow on a computer.
type wfRun struct {
	AgentID  string
	Hostname string
	Revision int
	State    string
	Job      store.Job
}

type workflowRow struct {
	store.Workflow
	Steps  int
	Counts map[string]int
}

type workflowsData struct {
	Rows []workflowRow
	// Module: the workflow module is published.
	Module bool
}

type workflowData struct {
	New         bool
	W           store.Workflow
	Doc         workflow.Document
	Latest      int // newest revision; W.Revision may be an older one
	Revisions   []store.Workflow
	Packages    []store.Package
	Groups      []store.Group
	Runs        []wfRun
	Counts      map[string]int
	Module      bool
	Assignments []assignmentView
	// Error: the posted workflow is not valid; the form shows it again.
	Error string
	// Editor choices.
	StepTypes, RuleTypes, InstallKinds []string
}

// workflowRuns returns the latest run of each workflow on each computer,
// by workflow id.
func (s *Server) workflowRuns(ctx context.Context, t string) (map[string][]wfRun, error) {
	jobs, err := s.store.ListModuleJobs(ctx, t, workflow.ModuleID, maxWorkflowJobs)
	if err != nil {
		return nil, err
	}
	agents, err := s.store.ListAgents(ctx, t)
	if err != nil {
		return nil, err
	}
	names := map[string]string{}
	for _, a := range agents {
		names[a.ID] = a.Host.Hostname
	}
	out := map[string][]wfRun{}
	seen := map[string]bool{}
	for _, j := range jobs { // newest first
		var p struct {
			WorkflowID string `json:"workflow_id"`
			Revision   int    `json:"revision"`
		}
		if json.Unmarshal(j.Params, &p) != nil || p.WorkflowID == "" || seen[p.WorkflowID+"/"+j.AgentID] {
			continue
		}
		seen[p.WorkflowID+"/"+j.AgentID] = true
		run := wfRun{AgentID: j.AgentID, Hostname: names[j.AgentID], Revision: p.Revision, Job: j, State: wfRunning}
		switch {
		case j.State == store.JobSucceeded:
			var res workflow.Result
			_ = json.Unmarshal(j.Result, &res)
			run.State = wfOK
			if res.Compliant {
				run.State = wfCompliant
			}
		case j.State.Final():
			run.State = wfFailed
		}
		out[p.WorkflowID] = append(out[p.WorkflowID], run)
	}
	for _, runs := range out {
		sort.Slice(runs, func(i, j int) bool { return strings.ToLower(runs[i].Hostname) < strings.ToLower(runs[j].Hostname) })
	}
	return out, nil
}

func countRuns(runs []wfRun) map[string]int {
	c := map[string]int{}
	for _, r := range runs {
		c[r.State]++
	}
	return c
}

func (s *Server) handleWorkflows(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	list, err := s.store.ListWorkflows(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	runs, err := s.workflowRuns(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var d workflowsData
	_, _, err = s.publishedModule(r.Context(), workflow.ModuleID)
	d.Module = err == nil
	for _, wf := range list {
		row := workflowRow{Workflow: wf, Counts: countRuns(runs[wf.ID])}
		if doc, err := workflow.Parse(wf.Document); err == nil {
			row.Steps = len(doc.Steps)
		}
		d.Rows = append(d.Rows, row)
	}
	s.render(w, r, "workflows", s.T(r, "Workflow di distribuzione"), d)
}

// workflowForm fills the editor data common to a new and an existing
// workflow.
func (s *Server) workflowForm(r *http.Request, t string, d *workflowData) error {
	var err error
	if d.Packages, err = s.store.ListPackages(r.Context(), t); err != nil {
		return err
	}
	groups, err := s.visibleGroups(r, t)
	if err != nil {
		return err
	}
	d.Groups = groups
	_, _, err = s.publishedModule(r.Context(), workflow.ModuleID)
	d.Module = err == nil
	d.StepTypes, d.RuleTypes, d.InstallKinds = workflow.StepTypes, workflow.RuleTypes, workflow.InstallKinds
	return nil
}

func (s *Server) handleWorkflow(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	d := workflowData{}
	id := r.PathValue("id")
	if id == "" {
		d.New = true
		d.Doc.Steps = []workflow.Step{{Type: workflow.StepInstall}}
		if err := s.workflowForm(r, t, &d); err != nil {
			s.fail(w, r, err)
			return
		}
		s.render(w, r, "workflow", s.T(r, "Nuovo workflow"), d)
		return
	}
	if !ids.IsUUID(id) {
		http.NotFound(w, r)
		return
	}
	rev, _ := strconv.Atoi(r.URL.Query().Get("rev"))
	wf, err := s.store.GetWorkflow(r.Context(), t, id, rev)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d.W = wf
	if doc, err := workflow.Parse(wf.Document); err == nil {
		d.Doc = *doc
	}
	if d.Revisions, err = s.store.WorkflowRevisions(r.Context(), t, id); err != nil {
		s.fail(w, r, err)
		return
	}
	d.Latest = d.Revisions[0].Revision
	runs, err := s.workflowRuns(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d.Runs, d.Counts = runs[id], countRuns(runs[id])
	if d.Assignments, err = s.assignmentsFor(r, t, id); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.workflowForm(r, t, &d); err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, "workflow", wf.Name, d)
}

var wfField = regexp.MustCompile(`^(d|s\.(\d+))\.r\.(\d+)\.([a-z_]+)$|^s\.(\d+)\.([a-z_]+)$`)

// parseWorkflowForm reads the editor: "d.match" and "d.r.N.<field>" for the
// detection, "s.N.<field>", "s.N.match" and "s.N.r.M.<field>" for the steps,
// ordered by "s.N.order" (the editor renumbers on move) and then N. Rows
// without a type are blank and left out.
func parseWorkflowForm(form url.Values) workflow.Document {
	type ruleKey struct{ step, rule int } // step -1: detection
	rules := map[ruleKey]map[string]string{}
	steps := map[int]map[string]string{}
	for k, vs := range form {
		m := wfField.FindStringSubmatch(k)
		if m == nil || len(vs) == 0 {
			continue
		}
		v := vs[0]
		if m[1] != "" {
			key := ruleKey{step: -1}
			if m[2] != "" {
				key.step, _ = strconv.Atoi(m[2])
			}
			key.rule, _ = strconv.Atoi(m[3])
			if rules[key] == nil {
				rules[key] = map[string]string{}
			}
			rules[key][m[4]] = v
			continue
		}
		n, _ := strconv.Atoi(m[5])
		if steps[n] == nil {
			steps[n] = map[string]string{}
		}
		steps[n][m[6]] = v
	}
	conds := func(step int, match string) workflow.Conditions {
		c := workflow.Conditions{Match: match}
		var keys []int
		for k := range rules {
			if k.step == step {
				keys = append(keys, k.rule)
			}
		}
		sort.Ints(keys)
		for _, i := range keys {
			f := rules[ruleKey{step, i}]
			if f["type"] == "" {
				continue
			}
			rule := workflow.Rule{Type: f["type"], Negate: f["negate"] != ""}
			switch rule.Type {
			case workflow.RuleScript:
				rule.Script = f["script"]
			case workflow.RuleUserGroup, workflow.RuleComputerGroup:
				rule.Name = strings.TrimSpace(f["name"])
			default:
				rule.Op, rule.Value = f["op"], strings.TrimSpace(f["value"])
				if rule.Op == workflow.OpExists {
					rule.Value = ""
				}
				if rule.Type == workflow.RuleApp {
					rule.Name = strings.TrimSpace(f["name"])
				} else {
					rule.Path = strings.TrimSpace(f["path"])
				}
				if rule.Type == workflow.RuleRegistry {
					rule.Name = strings.TrimSpace(f["name"])
				}
			}
			c.Rules = append(c.Rules, rule)
		}
		return c
	}
	d := workflow.Document{Detection: conds(-1, form.Get("d.match"))}
	var order []int
	for n := range steps {
		order = append(order, n)
	}
	pos := func(n int) int {
		if p, err := strconv.Atoi(steps[n]["order"]); err == nil {
			return p
		}
		return n
	}
	sort.Slice(order, func(i, j int) bool {
		if pi, pj := pos(order[i]), pos(order[j]); pi != pj {
			return pi < pj
		}
		return order[i] < order[j]
	})
	for _, n := range order {
		f := steps[n]
		if f["type"] == "" {
			continue
		}
		st := workflow.Step{Name: strings.TrimSpace(f["name"]), Type: f["type"], When: conds(n, f["match"]),
			ContinueOnError: f["continue"] != ""}
		// Only the fields of the step's type: the editor keeps the others
		// hidden, with what was typed before changing type.
		pkg := f["package"]
		switch st.Type {
		case workflow.StepScript:
			st.Script = f["script"]
		case workflow.StepCommand:
			st.Command, st.Args = strings.TrimSpace(f["command"]), f["args"]
		case workflow.StepDownload:
			if st.Package = pkg; pkg == "" {
				st.URL, st.SHA256 = strings.TrimSpace(f["url"]), strings.TrimSpace(f["sha256"])
			}
			st.SaveAs = strings.TrimSpace(f["save_as"])
		case workflow.StepHTTP:
			st.URL, st.Method, st.Headers, st.Body = strings.TrimSpace(f["url"]), f["method"], f["headers"], f["body"]
			st.ContentType = strings.TrimSpace(f["content_type"])
		case workflow.StepInstall:
			if st.Package = pkg; pkg == "" {
				st.File = strings.TrimSpace(f["file"])
			}
			st.Kind, st.Args, st.AllowUnsigned = f["kind"], f["args"], f["unsigned"] != ""
		}
		st.TimeoutSeconds, _ = strconv.Atoi(strings.TrimSpace(f["timeout"]))
		st.TimeoutSeconds *= 60 // minutes in the form
		for _, c := range strings.FieldsFunc(f["codes"], func(r rune) bool { return r == ',' || r == ' ' }) {
			if st.Type != workflow.StepCommand && st.Type != workflow.StepInstall {
				break
			}
			if n, err := strconv.Atoi(c); err == nil {
				st.SuccessCodes = append(st.SuccessCodes, n)
			}
		}
		d.Steps = append(d.Steps, st)
	}
	return d
}

// handleSaveWorkflow saves the editor as a new revision, or deletes the
// workflow.
func (s *Server) handleSaveWorkflow(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, s.T(r, "richiesta non valida"), http.StatusBadRequest)
		return
	}
	op := sessionFrom(r.Context()).data.Operator
	d := workflowData{}
	id := r.PathValue("id")
	if id == "" {
		d.New, id = true, ids.NewUUID()
	} else if !ids.IsUUID(id) {
		http.NotFound(w, r)
		return
	} else {
		cur, err := s.store.GetWorkflow(r.Context(), t, id, 0)
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			s.fail(w, r, err)
			return
		}
		d.W = cur
		if r.PostFormValue("delete") != "" {
			if err := s.store.DeleteWorkflow(r.Context(), t, id); err != nil && !errors.Is(err, store.ErrNotFound) {
				s.fail(w, r, err)
				return
			}
			s.audit(r.Context(), t, op, "workflow.deleted", id, map[string]any{"name": cur.Name})
			s.flash(w, r, s.Tf(r, "Workflow %s eliminato.", cur.Name), "/workflows")
			return
		}
	}
	d.W.ID = id
	d.W.Name = strings.TrimSpace(r.PostFormValue("name"))
	d.W.Description = strings.TrimSpace(r.PostFormValue("description"))
	d.W.Comment = strings.TrimSpace(r.PostFormValue("comment"))
	d.Doc = parseWorkflowForm(r.PostForm)
	again := func(msg string) {
		if err := s.workflowForm(r, t, &d); err != nil {
			s.fail(w, r, err)
			return
		}
		if !d.New {
			d.Revisions, _ = s.store.WorkflowRevisions(r.Context(), t, id)
			if len(d.Revisions) > 0 {
				d.Latest = d.Revisions[0].Revision
				d.W.Revision = d.Latest
			}
		}
		d.Error = msg
		w.WriteHeader(http.StatusUnprocessableEntity)
		title := d.W.Name
		if d.New {
			title = s.T(r, "Nuovo workflow")
		}
		s.render(w, r, "workflow", title, d)
	}
	if name, ok := groupName(d.W.Name); !ok || len(d.W.Description) > 1000 || len(d.W.Comment) > 1000 {
		again(s.T(r, "Dai al workflow un nome (al massimo 64 caratteri)."))
		return
	} else {
		d.W.Name = name
	}
	if err := d.Doc.Validate(); err != nil {
		again(s.Tf(r, "Workflow non valido: %v", err))
		return
	}
	names := map[string]bool{}
	for _, sha := range d.Doc.Packages() {
		p, err := s.store.GetPackage(r.Context(), t, sha)
		if err != nil {
			again(s.T(r, "Un pacchetto del workflow non è più nella libreria."))
			return
		}
		if n := strings.ToLower(p.FileName); names[n] {
			again(s.T(r, "Due pacchetti del workflow hanno lo stesso nome di file."))
			return
		}
		names[strings.ToLower(p.FileName)] = true
	}
	raw, err := json.Marshal(d.Doc)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rev, err := s.store.SaveWorkflow(r.Context(), store.Workflow{TenantID: t, ID: id, Name: d.W.Name, Description: d.W.Description,
		Document: raw, Comment: d.W.Comment, Author: op.Username})
	if errors.Is(err, store.ErrWorkflowExists) {
		again(s.T(r, "Esiste già un workflow con questo nome."))
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r.Context(), t, op, "workflow.saved", id, map[string]any{"name": d.W.Name, "revision": rev, "comment": d.W.Comment,
		"workflow": json.RawMessage(raw)})
	s.flash(w, r, s.Tf(r, "Workflow %s salvato: revisione %d.", d.W.Name, rev), "/workflows/"+id)
}

// workflowJob builds the job running the latest revision of a workflow on
// targets.
func (s *Server) workflowJob(r *http.Request, t, id string, targets []string) (*openrmmv1.JobRequest, string) {
	wf, err := s.store.GetWorkflow(r.Context(), t, id, 0)
	if err != nil {
		return nil, s.T(r, "Workflow non trovato.")
	}
	doc, err := workflow.Parse(wf.Document)
	if err != nil {
		return nil, s.Tf(r, "Workflow non valido: %v", err)
	}
	man, mod, err := s.publishedModule(r.Context(), workflow.ModuleID)
	if err != nil {
		return nil, s.T(r, "Pubblica prima il modulo workflow dalla pagina Moduli.")
	}
	var refs []*openrmmv1.PackageRef
	for _, sha := range doc.Packages() {
		p, err := s.store.GetPackage(r.Context(), t, sha)
		if err != nil {
			return nil, s.T(r, "Un pacchetto del workflow non è più nella libreria.")
		}
		b, _ := hex.DecodeString(p.SHA256)
		refs = append(refs, &openrmmv1.PackageRef{Sha256: b, FileName: p.FileName, Size: p.Size})
		// A package allowed unsigned in the library installs unsigned.
		for i := range doc.Steps {
			if doc.Steps[i].Package == sha && p.AllowUnsigned {
				doc.Steps[i].AllowUnsigned = true
			}
		}
	}
	raw, err := json.Marshal(workflow.Params{WorkflowID: wf.ID, Name: wf.Name, Revision: wf.Revision, Workflow: *doc})
	if err != nil {
		return nil, err.Error()
	}
	req := &openrmmv1.JobRequest{TenantId: t, Module: man.ID, ModuleVersion: man.Version, ModuleSha256: mod.ManifestSHA256,
		Action: workflow.Action, ParamsJson: raw, TtlSeconds: ttlFrom(r), RequestNonce: jobreq.NewRequestNonce(), Packages: refs}
	if len(targets) == 1 {
		req.AgentId = targets[0]
	} else {
		req.AgentIds = targets
	}
	if err := jobreq.Validate(req); err != nil {
		return nil, s.Tf(r, "Richiesta non valida: %v", err)
	}
	return req, ""
}
