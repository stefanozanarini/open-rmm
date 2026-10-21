package modules

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Parameter forms. A module may describe the parameters of its actions in
// params.json, next to manifest.json; the console turns it into form fields
// and builds the job parameters from them, checked against the same
// description. It is not part of the signed manifest (agents ignore it):
// what an agent runs is decided by the parameters in the signed job.
//
//	{ "install": [ { "name": "classifications", "type": "multi",
//	                 "label": {"it": "Classificazioni", "en": "Classifications"},
//	                 "options": [ {"value": "security", "label": {"it": "Sicurezza", "en": "Security"}} ],
//	                 "default": ["security"] } ] }

// ParamsFile is the name of the parameter description in a module.
const ParamsFile = "params.json"

// Parameter types.
const (
	ParamString = "string" // one line of text
	ParamText   = "text"   // several lines
	ParamInt    = "int"    // integer within min/max
	ParamBool   = "bool"
	ParamEnum   = "enum"  // one of options
	ParamMulti  = "multi" // any of options
	ParamList   = "list"  // free strings, one per line or comma separated
)

var paramNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,40}$`)

// Text is a label in several languages, by language code.
type Text map[string]string

// In returns the text in lang, falling back to English, then to any.
func (t Text) In(lang string) string {
	if v, ok := t[lang]; ok {
		return v
	}
	if v, ok := t["en"]; ok {
		return v
	}
	for _, v := range t {
		return v
	}
	return ""
}

// ParamOption is a choice of an enum or multi parameter.
type ParamOption struct {
	Value string `json:"value"`
	Label Text   `json:"label,omitempty"`
}

// ParamSpec describes one parameter.
type ParamSpec struct {
	Name     string          `json:"name"`
	Type     string          `json:"type"`
	Label    Text            `json:"label"`
	Help     Text            `json:"help,omitempty"`
	Default  json.RawMessage `json:"default,omitempty"`
	Options  []ParamOption   `json:"options,omitempty"`
	Min      *int64          `json:"min,omitempty"`
	Max      *int64          `json:"max,omitempty"`
	Required bool            `json:"required,omitempty"`
}

// ParamSchema maps action names to their parameters.
type ParamSchema map[string][]ParamSpec

// ParseParams decodes and checks a params.json against the manifest.
func ParseParams(raw []byte, m *Manifest) (ParamSchema, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var s ParamSchema
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("%s: %w", ParamsFile, err)
	}
	for action, specs := range s {
		if _, ok := m.Actions[action]; !ok {
			return nil, fmt.Errorf("%s: unknown action %q", ParamsFile, action)
		}
		seen := map[string]bool{}
		for _, p := range specs {
			if !paramNameRe.MatchString(p.Name) || seen[p.Name] {
				return nil, fmt.Errorf("%s: %s: invalid or duplicate parameter %q", ParamsFile, action, p.Name)
			}
			seen[p.Name] = true
			switch p.Type {
			case ParamString, ParamText, ParamInt, ParamBool, ParamList:
			case ParamEnum, ParamMulti:
				if len(p.Options) == 0 {
					return nil, fmt.Errorf("%s: %s.%s: options required", ParamsFile, action, p.Name)
				}
			default:
				return nil, fmt.Errorf("%s: %s.%s: unknown type %q", ParamsFile, action, p.Name, p.Type)
			}
		}
	}
	return s, nil
}

// DefaultString is the default value as form text: the value of a string,
// int or enum, "true" for a bool, one entry per line for a list.
func (p ParamSpec) DefaultString() string {
	if len(p.Default) == 0 {
		return ""
	}
	var v any
	if json.Unmarshal(p.Default, &v) != nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatInt(int64(x), 10)
	case bool:
		if x {
			return "true"
		}
		return ""
	case []any:
		var out []string
		for _, e := range x {
			out = append(out, fmt.Sprint(e))
		}
		return strings.Join(out, "\n")
	}
	return ""
}

// DefaultHas tells whether a multi parameter's default includes value.
func (p ParamSpec) DefaultHas(value string) bool {
	var vs []string
	_ = json.Unmarshal(p.Default, &vs)
	return slices.Contains(vs, value)
}

// BuildParams turns form values into job parameters. get returns the
// values of a field (several for a multi). Empty optional fields are left
// out, so the module applies its own default.
func BuildParams(specs []ParamSpec, get func(name string) []string) (map[string]any, error) {
	out := map[string]any{}
	for _, p := range specs {
		vals := get(p.Name)
		first := ""
		if len(vals) > 0 {
			first = strings.TrimSpace(vals[0])
		}
		label := p.Label.In("en")
		switch p.Type {
		case ParamBool:
			out[p.Name] = first == "true" || first == "on" || first == "1"
		case ParamInt:
			if first == "" {
				if p.Required {
					return nil, fmt.Errorf("%s is required", label)
				}
				continue
			}
			n, err := strconv.ParseInt(first, 10, 64)
			if err != nil || (p.Min != nil && n < *p.Min) || (p.Max != nil && n > *p.Max) {
				return nil, fmt.Errorf("%s: invalid number", label)
			}
			out[p.Name] = n
		case ParamEnum:
			if first == "" && !p.Required {
				continue
			}
			if !slices.ContainsFunc(p.Options, func(o ParamOption) bool { return o.Value == first }) {
				return nil, fmt.Errorf("%s: invalid choice", label)
			}
			out[p.Name] = first
		case ParamMulti:
			var sel []string
			for _, v := range vals {
				if !slices.ContainsFunc(p.Options, func(o ParamOption) bool { return o.Value == v }) {
					return nil, fmt.Errorf("%s: invalid choice", label)
				}
				sel = append(sel, v)
			}
			if len(sel) == 0 {
				if p.Required {
					return nil, fmt.Errorf("%s: choose at least one", label)
				}
				continue
			}
			out[p.Name] = sel
		case ParamList:
			// One text field (a value per line), or several fields.
			var items []string
			for _, v := range vals {
				for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' }) {
					if f = strings.TrimSpace(f); f != "" && !slices.Contains(items, f) {
						items = append(items, f)
					}
				}
			}
			if len(items) == 0 {
				if p.Required {
					return nil, fmt.Errorf("%s is required", label)
				}
				continue
			}
			out[p.Name] = items
		default: // string, text
			if first == "" {
				if p.Required {
					return nil, fmt.Errorf("%s is required", label)
				}
				continue
			}
			if p.Type == ParamText && len(vals) > 0 {
				first = vals[0]
			}
			out[p.Name] = first
		}
	}
	if len(out) > 64 {
		return nil, errors.New("too many parameters")
	}
	return out, nil
}
