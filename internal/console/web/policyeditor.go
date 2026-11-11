package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/modules"
	"github.com/stefanozanarini/tempra-rmm/internal/policy"
)

// The policy editor: one card per published module with its actions; an
// action switched on becomes a rule (newest module version) with its
// interval, condition, window and parameters. Rules the editor cannot show
// (an older module version without the action, a second rule for the same
// action) are kept as they are; the JSON editor remains for those.

// policyModuleView is a module card of the editor.
type policyModuleView struct {
	ID, Version, Description string
	Actions                  []policyActionView
	Active                   int // actions switched on
}

// policyActionView is an action of a module card.
type policyActionView struct {
	Key, Name, Description string // Key: module.action, prefix of the field names
	On                     bool
	Every                  string
	EveryOptions           []string
	Cond, CondValue        string // condition type and value
	CondJSON               string // an advanced condition (all, any, not)
	Days                   map[string]bool
	Start, End             string
	Known                  bool // parameters described by params.json
	Fields                 []paramField
	ParamsJSON             string // parameters without a description
}

// Interval choices of the editor; another saved interval is added to them.
var policyIntervals = []string{"5m", "15m", "30m", "1h", "6h", "12h", "24h", "168h"}

var weekdayOrder = []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}

var dayNames = map[string]string{"mon": "lun", "tue": "mar", "wed": "mer", "thu": "gio", "fri": "ven", "sat": "sab", "sun": "dom"}

// intervalName is an interval as shown to operators: 15m, 24h…
func intervalName(lang, s string) string {
	d, err := time.ParseDuration(s)
	if err != nil {
		return s
	}
	switch {
	case d == 7*24*time.Hour:
		return tr(lang, "settimana (7 giorni)")
	case d == 24*time.Hour:
		return tr(lang, "giorno (24 ore)")
	case d%time.Hour == 0 && d > time.Hour:
		return trf(lang, "%d ore", int(d/time.Hour))
	case d == time.Hour:
		return tr(lang, "1 ora")
	case d%time.Minute == 0:
		return trf(lang, "%d minuti", int(d/time.Minute))
	}
	return s
}

// Simple conditions of the editor, by type.
const (
	condNone     = ""
	condService  = "service_exists"
	condFile     = "file_exists"
	condRegistry = "registry_key_exists"
	condClient   = "client"
	condServer   = "server"
	condJSON     = "json"
)

// latestPolicyModules returns the newest version of every published module
// that may run in a policy (no ad-hoc scripts, no interactive shell).
func (s *Server) latestPolicyModules(ctx context.Context) ([]store.Module, map[string]*modules.Manifest, error) {
	mods, err := s.store.ListModules(ctx)
	if err != nil {
		return nil, nil, err
	}
	best := map[string]store.Module{}
	for _, m := range mods {
		if b, ok := best[m.ID]; !ok || compareVersions(m.Version, b.Version) > 0 {
			best[m.ID] = m
		}
	}
	var out []store.Module
	mans := map[string]*modules.Manifest{}
	for _, m := range best {
		man, err := modules.ParseManifest(m.Manifest)
		if err != nil || man.HasCapability(modules.CapAdHocScript) || man.Interactive() {
			continue
		}
		out = append(out, m)
		mans[m.ID] = man
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, mans, nil
}

func actionKey(module, action string) string { return module + "." + action }

// policyEditor builds the module cards; rules fills in the actions of an
// existing policy and returns the rules it could not place.
func (s *Server) policyEditor(ctx context.Context, lang string, rules []formRule) ([]policyModuleView, []formRule, error) {
	mods, mans, err := s.latestPolicyModules(ctx)
	if err != nil {
		return nil, nil, err
	}
	byKey := map[string]formRule{}
	var extra []formRule
	for _, r := range rules {
		k := actionKey(r.Module, r.Action)
		man := mans[r.Module]
		if _, dup := byKey[k]; dup || man == nil {
			extra = append(extra, r)
			continue
		}
		if _, ok := man.Actions[r.Action]; !ok {
			extra = append(extra, r)
			continue
		}
		byKey[k] = r
	}
	var out []policyModuleView
	for _, m := range mods {
		man := mans[m.ID]
		sch, known := s.paramSchema(m, man)
		mv := policyModuleView{ID: m.ID, Version: m.Version, Description: man.Description}
		names := make([]string, 0, len(man.Actions))
		for a := range man.Actions {
			names = append(names, a)
		}
		sort.Strings(names)
		for _, a := range names {
			k := actionKey(m.ID, a)
			av := policyActionView{Key: k, Name: a, Description: man.Actions[a].Description, Every: "24h", Days: map[string]bool{}}
			specs, hasSpecs := sch[a]
			av.Known = known && hasSpecs
			var params map[string]any
			if r, ok := byKey[k]; ok {
				av.On, av.Every = true, shortDuration(r.Every)
				_ = json.Unmarshal(r.Params, &params)
				av.Cond, av.CondValue, av.CondJSON = conditionForm(r.When)
				if w := r.Window; w != nil {
					av.Start, av.End = w.Start, w.End
					for _, d := range w.Days {
						av.Days[d] = true
					}
				}
				if !av.Known && len(r.Params) > 0 {
					av.ParamsJSON = string(r.Params)
				}
				mv.Active++
			}
			if av.Known {
				av.Fields = paramFields(lang, specs)
				for i := range av.Fields {
					av.Fields[i].Prefix = k + "."
					if params != nil {
						fillField(&av.Fields[i], params[av.Fields[i].Name], av.On)
					}
				}
			}
			av.EveryOptions = policyIntervals
			if !slices.Contains(policyIntervals, av.Every) {
				av.EveryOptions = append([]string{av.Every}, policyIntervals...)
			}
			mv.Actions = append(mv.Actions, av)
		}
		out = append(out, mv)
	}
	return out, extra, nil
}

// shortDuration writes 24h0m0s as 24h.
func shortDuration(s string) string {
	d, err := time.ParseDuration(s)
	if err != nil {
		return s
	}
	out := d.String()
	out = strings.TrimSuffix(out, "0s")
	out = strings.TrimSuffix(out, "0m")
	if out == "" {
		return s
	}
	return out
}

// conditionForm turns a condition into the editor's fields.
func conditionForm(c *policy.Condition) (typ, value, raw string) {
	switch {
	case c == nil:
		return condNone, "", ""
	case c.ServiceExists != "" && c.All == nil && c.Any == nil && c.Not == nil:
		return condService, c.ServiceExists, ""
	case c.FileExists != "" && c.All == nil && c.Any == nil && c.Not == nil:
		return condFile, c.FileExists, ""
	case c.RegistryKeyExists != "" && c.All == nil && c.Any == nil && c.Not == nil:
		return condRegistry, c.RegistryKeyExists, ""
	case c.OSFamily == "client" && c.All == nil && c.Any == nil && c.Not == nil:
		return condClient, "", ""
	case c.OSFamily == "server" && c.All == nil && c.Any == nil && c.Not == nil:
		return condServer, "", ""
	}
	b, _ := json.Marshal(c)
	return condJSON, "", string(b)
}

// fillField sets a parameter field to a saved value. A field switched off
// in a saved rule (absent) shows as empty rather than with its default.
func fillField(f *paramField, v any, saved bool) {
	if !saved {
		return
	}
	switch f.Type {
	case modules.ParamMulti:
		set := map[string]bool{}
		if l, ok := v.([]any); ok {
			for _, x := range l {
				if s, ok := x.(string); ok {
					set[s] = true
				}
			}
		}
		for i := range f.Options {
			f.Options[i].Checked = set[f.Options[i].Value]
		}
		return
	case modules.ParamBool:
		if b, ok := v.(bool); ok && b {
			f.Value = "true"
		} else {
			f.Value = ""
		}
		return
	case modules.ParamList:
		if l, ok := v.([]any); ok {
			parts := make([]string, 0, len(l))
			for _, x := range l {
				if s, ok := x.(string); ok {
					parts = append(parts, s)
				}
			}
			f.Value = strings.Join(parts, "\n")
			return
		}
	}
	switch x := v.(type) {
	case nil:
		f.Value = ""
	case string:
		f.Value = x
	case float64:
		f.Value = strconv.FormatFloat(x, 'f', -1, 64)
	default:
		b, _ := json.Marshal(x)
		f.Value = string(b)
	}
	if f.Type == modules.ParamEnum {
		for i := range f.Options {
			f.Options[i].Checked = f.Options[i].Value == f.Value
		}
	}
}

var ruleIDClean = regexp.MustCompile(`[^a-z0-9-]+`)

// ruleID is the id of the rule of an action: module-action.
func ruleID(module, action string) string {
	id := strings.Trim(ruleIDClean.ReplaceAllString(strings.ToLower(module+"-"+action), "-"), "-")
	if id == "" || id[0] < 'a' || id[0] > 'z' {
		id = "r-" + id
	}
	if len(id) > 41 {
		id = id[:41]
	}
	return id
}

// editorRules reads the editor's form into rules, followed by the rules
// the editor kept as they were (field "extra"). On a mistake it still
// returns every rule it could read, for the form to show again, with the
// first problem.
func (s *Server) editorRules(r *http.Request) ([]formRule, error) {
	_ = r.ParseForm()
	mods, mans, err := s.latestPolicyModules(r.Context())
	if err != nil {
		return nil, err
	}
	var out []formRule
	var problem error
	fail := func(msg string) {
		if problem == nil {
			problem = errors.New(msg)
		}
	}
	for _, m := range mods {
		man := mans[m.ID]
		sch, known := s.paramSchema(m, man)
		names := make([]string, 0, len(man.Actions))
		for a := range man.Actions {
			names = append(names, a)
		}
		sort.Strings(names)
		for _, a := range names {
			k := actionKey(m.ID, a)
			if r.PostFormValue("on."+k) == "" {
				continue
			}
			fr := formRule{ID: ruleID(m.ID, a), Module: m.ID, Version: m.Version, Action: a, Every: r.PostFormValue("every." + k)}
			label := m.ID + " · " + a
			if specs, ok := sch[a]; known && ok {
				p, err := modules.BuildParams(specs, func(name string) []string { return r.PostForm["p."+k+"."+name] })
				if err != nil {
					fail(s.Tf(r, "%s: parametri non validi: %v", label, err))
				}
				if len(p) > 0 {
					fr.Params, _ = json.Marshal(p)
				}
			} else if raw := strings.TrimSpace(r.PostFormValue("pjson." + k)); raw != "" && raw != "{}" {
				var obj map[string]any
				if json.Unmarshal([]byte(raw), &obj) != nil {
					fail(s.Tf(r, "%s: i parametri devono essere un oggetto JSON", label))
				} else {
					fr.Params = json.RawMessage(raw)
				}
			}
			v := strings.TrimSpace(r.PostFormValue("condv." + k))
			switch typ := r.PostFormValue("cond." + k); typ {
			case condService, condFile, condRegistry:
				if v == "" {
					fail(s.Tf(r, "%s: indica il nome del servizio, del file o della chiave", label))
					break
				}
				c := policy.Condition{}
				switch typ {
				case condService:
					c.ServiceExists = v
				case condFile:
					c.FileExists = v
				default:
					c.RegistryKeyExists = v
				}
				fr.When = &c
			case condClient, condServer:
				fr.When = &policy.Condition{OSFamily: typ}
			case condJSON:
				var c policy.Condition
				if err := json.Unmarshal([]byte(r.PostFormValue("condjson."+k)), &c); err != nil {
					fail(s.Tf(r, "%s: condizione non valida", label))
				} else {
					fr.When = &c
				}
			}
			start, end := r.PostFormValue("start."+k), r.PostFormValue("end."+k)
			var days []string
			for _, d := range weekdayOrder {
				if r.PostFormValue("day."+k+"."+d) != "" {
					days = append(days, d)
				}
			}
			if start != "" || end != "" || len(days) > 0 {
				if start == "" || end == "" {
					fail(s.Tf(r, "%s: la finestra oraria richiede inizio e fine", label))
				} else {
					fr.Window = &policy.Window{Days: days, Start: start, End: end}
				}
			}
			out = append(out, fr)
		}
	}
	if raw := r.PostFormValue("extra"); raw != "" {
		var extra []formRule
		if err := json.Unmarshal([]byte(raw), &extra); err != nil {
			return out, err
		}
		out = append(out, extra...)
	}
	return out, problem
}
