package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/modules"
)

// Action parameters as form fields, from the module's params.json: stored
// with the published module, or shipped with the console for the same
// version (modules published before params.json existed). Without one, the
// form falls back to a JSON text field.

type paramField struct {
	modules.ParamSpec
	Text, Help, Value string
	MinS, MaxS        string // bounds of an int, "" when unbounded
	Options           []paramOption
}

type paramOption struct {
	Value, Label string
	Checked      bool
}

// paramSchema returns the parameter description of a module version.
func (s *Server) paramSchema(m store.Module, man *modules.Manifest) (modules.ParamSchema, bool) {
	raw := m.Params
	if len(raw) == 0 {
		raw = s.modules.Params(m.ID, m.Version)
	}
	if len(raw) == 0 {
		return nil, false
	}
	sch, err := modules.ParseParams(raw, man)
	if err != nil {
		s.log.Warn("module parameters unreadable", "module", m.ID, "version", m.Version, "err", err)
		return nil, false
	}
	return sch, true
}

// paramFields prepares the fields of an action in the operator's language.
func paramFields(lang string, specs []modules.ParamSpec) []paramField {
	var out []paramField
	for _, p := range specs {
		f := paramField{ParamSpec: p, Text: p.Label.In(lang), Help: p.Help.In(lang), Value: p.DefaultString()}
		if p.Min != nil {
			f.MinS = strconv.FormatInt(*p.Min, 10)
		}
		if p.Max != nil {
			f.MaxS = strconv.FormatInt(*p.Max, 10)
		}
		for _, o := range p.Options {
			label := o.Label.In(lang)
			if label == "" {
				label = o.Value
			}
			f.Options = append(f.Options, paramOption{Value: o.Value, Label: label,
				Checked: (p.Type == modules.ParamMulti && p.DefaultHas(o.Value)) || (p.Type == modules.ParamEnum && f.Value == o.Value)})
		}
		out = append(out, f)
	}
	return out
}

// jobParams builds the parameters of a job from the form: the fields of
// the action's description, or the JSON text field when the module has
// none. msg is for the operator.
func (s *Server) jobParams(r *http.Request, mod store.Module, man *modules.Manifest, action string) (map[string]any, string) {
	_ = r.ParseForm()
	if sch, ok := s.paramSchema(mod, man); ok {
		if specs, ok := sch[action]; ok {
			p, err := modules.BuildParams(specs, func(name string) []string { return r.PostForm["p."+name] })
			if err != nil {
				return nil, s.Tf(r, "Parametri non validi: %s", err.Error())
			}
			return p, ""
		}
	}
	// Form fields without a description to read them: refusing is safer
	// than running the action with its defaults (e.g. every update instead
	// of the selected ones).
	for k := range r.PostForm {
		if strings.HasPrefix(k, "p.") {
			return nil, s.T(r, "Questo modulo non descrive i suoi parametri: impossibile eseguire l'azione con i valori scelti.")
		}
	}
	params := map[string]any{}
	if raw := strings.TrimSpace(r.PostFormValue("params")); raw != "" {
		if err := json.Unmarshal([]byte(raw), &params); err != nil {
			return nil, s.T(r, "I parametri devono essere un oggetto JSON.")
		}
	}
	return params, ""
}
