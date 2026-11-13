// Package workflow describes software distribution workflows: detection
// rules that tell whether a computer is already compliant, and ordered
// steps (scripts, commands, downloads, HTTP calls, installations), each run
// only when its conditions hold (registry, files, installed applications,
// Active Directory groups of the user and of the computer).
//
// A workflow revision is a Document. The console signs it as the
// parameters of a job of the workflow module, with the library packages it
// uses; the module interprets it on the endpoint. The module runs code of
// the job, like the script module, so it needs an operator's approval with
// MFA and the endpoint's local policy AllowAdHocScripts.
package workflow

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"unicode"

	"github.com/stefanozanarini/tempra-rmm/internal/pkgref"
)

const (
	ModuleID = "workflow"
	Action   = "run"

	MaxSteps     = 50
	MaxRules     = 20
	MaxText      = 64 << 10 // a script, a body
	MaxDocument  = 512 << 10
	MaxStepName  = 128
	MaxShortText = 2048 // paths, arguments, names
)

// Step types.
const (
	StepScript   = "script"   // PowerShell script
	StepCommand  = "command"  // executable with arguments
	StepDownload = "download" // library package or URL to a file
	StepHTTP     = "http"     // GET or POST request
	StepInstall  = "install"  // MSI or setup program, silently
)

// Rule types.
const (
	RuleScript        = "script"         // PowerShell returning $true
	RuleRegistry      = "registry"       // key or value
	RuleFile          = "file"           // file or folder, file version
	RuleApp           = "app"            // installed application, version
	RuleUserGroup     = "user_group"     // AD group of the user (logged on, or last)
	RuleComputerGroup = "computer_group" // AD group of the computer account
)

// Rule operators.
const (
	OpExists    = "exists"
	OpEquals    = "equals"
	OpVersionGE = "version_ge"
)

// StepTypes and RuleTypes list the types in the editor's order.
var (
	StepTypes = []string{StepScript, StepCommand, StepDownload, StepHTTP, StepInstall}
	RuleTypes = []string{RuleApp, RuleRegistry, RuleFile, RuleScript, RuleUserGroup, RuleComputerGroup}
)

// InstallKinds are the installer kinds of an install step ("" guesses from
// the file extension).
var InstallKinds = []string{"", "msi", "exe", "inno", "nullsoft", "burn"}

// Document is a workflow revision.
type Document struct {
	// Detection: when its rules hold the computer is compliant and the
	// steps are skipped; after the steps they must hold for success. No
	// rules: the steps always run.
	Detection Conditions `json:"detection"`
	Steps     []Step     `json:"steps"`
}

// Conditions are rules joined by AND (Match "all") or OR ("any").
type Conditions struct {
	Match string `json:"match,omitempty"` // all (default) | any
	Rules []Rule `json:"rules,omitempty"`
}

// Rule is a check run on the endpoint.
type Rule struct {
	Type   string `json:"type"`
	Negate bool   `json:"negate,omitempty"` // true when the check fails
	// script: the PowerShell code; true when its last output is $true.
	Script string `json:"script,omitempty"`
	// registry: key (HKLM:\SOFTWARE\…); file: path. Environment variables
	// (%ProgramFiles%) are expanded.
	Path string `json:"path,omitempty"`
	// registry: value name ("" for the key itself); app: display name, * for
	// any text; user_group / computer_group: group (DOMAIN\group or group).
	Name string `json:"name,omitempty"`
	// Op: registry exists | equals; file exists | version_ge; app exists
	// (installed) | version_ge.
	Op    string `json:"op,omitempty"`
	Value string `json:"value,omitempty"` // expected value or minimum version
}

// Step is an action of the workflow.
type Step struct {
	Name string     `json:"name,omitempty"`
	Type string     `json:"type"`
	When Conditions `json:"when"`
	// ContinueOnError: a failure is logged and the next step runs.
	ContinueOnError bool `json:"continue_on_error,omitempty"`
	TimeoutSeconds  int  `json:"timeout_seconds,omitempty"` // command, install, script; 0: 30 minutes

	Script string `json:"script,omitempty"` // script

	// command: program (cmd.exe, C:\…\tool.exe or a file downloaded
	// before) and arguments; install: arguments added to the defaults.
	Command string `json:"command,omitempty"`
	Args    string `json:"args,omitempty"`
	// SuccessCodes: exit codes meaning success (command default 0;
	// install default 0, 3010, 1641).
	SuccessCodes []int `json:"success_codes,omitempty"`

	// download, install: a library package by SHA-256, or (download, http)
	// a URL. A download from a URL may be checked against SHA256.
	Package string `json:"package,omitempty"`
	URL     string `json:"url,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	// download: where to save, a file name in the work folder or a full
	// path; install: the file to install, saved by a download step, when
	// it does not install a package.
	SaveAs string `json:"save_as,omitempty"`
	File   string `json:"file,omitempty"`

	// install: msi | exe | inno | nullsoft | burn ("" from the extension).
	Kind          string `json:"kind,omitempty"`
	AllowUnsigned bool   `json:"allow_unsigned,omitempty"`

	// http: method, headers ("Name: value" per line), body, and whether
	// to fail on a status outside 2xx (always, unless ContinueOnError).
	Method      string `json:"method,omitempty"`
	Headers     string `json:"headers,omitempty"`
	Body        string `json:"body,omitempty"`
	ContentType string `json:"content_type,omitempty"`
}

// Parse decodes and validates a document.
func Parse(raw []byte) (*Document, error) {
	if len(raw) > MaxDocument {
		return nil, fmt.Errorf("workflow larger than %d KiB", MaxDocument>>10)
	}
	var d Document
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return nil, err
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return &d, nil
}

// Validate checks a document; it also normalizes defaults.
func (d *Document) Validate() error {
	if err := d.Detection.validate("detection"); err != nil {
		return err
	}
	if len(d.Steps) == 0 {
		return errors.New("a workflow needs at least one step")
	}
	if len(d.Steps) > MaxSteps {
		return fmt.Errorf("at most %d steps", MaxSteps)
	}
	for i := range d.Steps {
		if err := d.Steps[i].validate(); err != nil {
			return fmt.Errorf("step %d: %w", i+1, err)
		}
	}
	if len(d.Packages()) > pkgref.MaxPerJob {
		return fmt.Errorf("at most %d library packages", pkgref.MaxPerJob)
	}
	if raw, _ := json.Marshal(d); len(raw) > MaxDocument {
		return fmt.Errorf("workflow larger than %d KiB", MaxDocument>>10)
	}
	return nil
}

func (c *Conditions) validate(where string) error {
	if c.Match == "" {
		c.Match = "all"
	}
	if c.Match != "all" && c.Match != "any" {
		return fmt.Errorf("%s: match must be all or any", where)
	}
	if len(c.Rules) > MaxRules {
		return fmt.Errorf("%s: at most %d rules", where, MaxRules)
	}
	for i, r := range c.Rules {
		if err := r.validate(); err != nil {
			return fmt.Errorf("%s, rule %d: %w", where, i+1, err)
		}
	}
	return nil
}

func (r Rule) validate() error {
	if err := texts(MaxShortText, r.Path, r.Name, r.Value); err != nil {
		return err
	}
	if err := texts(MaxText, r.Script); err != nil {
		return err
	}
	need := func(field, v string) error {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("%s is required", field)
		}
		return nil
	}
	ops := func(allowed ...string) error {
		if !slices.Contains(allowed, r.Op) {
			return fmt.Errorf("operator must be one of %s", strings.Join(allowed, ", "))
		}
		if r.Op != OpExists {
			return need("value", r.Value)
		}
		return nil
	}
	switch r.Type {
	case RuleScript:
		return need("script", r.Script)
	case RuleRegistry:
		if !regKeyOK(r.Path) {
			return errors.New("registry key must start with HKLM:\\, HKCU:\\, HKU:\\ or HKCR:\\")
		}
		return ops(OpExists, OpEquals)
	case RuleFile:
		if err := need("path", r.Path); err != nil {
			return err
		}
		return ops(OpExists, OpVersionGE)
	case RuleApp:
		if err := need("name", r.Name); err != nil {
			return err
		}
		return ops(OpExists, OpVersionGE)
	case RuleUserGroup, RuleComputerGroup:
		return need("group", r.Name)
	}
	return fmt.Errorf("unknown rule type %q", r.Type)
}

func regKeyOK(p string) bool {
	u := strings.ToUpper(p)
	for _, root := range []string{`HKLM:\`, `HKCU:\`, `HKU:\`, `HKCR:\`} {
		if strings.HasPrefix(u, root) && len(u) > len(root) {
			return true
		}
	}
	return false
}

// texts checks lengths and refuses control characters other than tab and
// line breaks.
func texts(max int, vs ...string) error {
	for _, v := range vs {
		if len(v) > max {
			return fmt.Errorf("text longer than %d characters", max)
		}
		if strings.ContainsFunc(v, func(c rune) bool { return unicode.IsControl(c) && c != '\t' && c != '\n' && c != '\r' }) {
			return errors.New("text with control characters")
		}
	}
	return nil
}

func (s *Step) validate() error {
	if err := texts(MaxStepName, s.Name); err != nil {
		return err
	}
	if err := texts(MaxShortText, s.Command, s.Args, s.URL, s.SHA256, s.SaveAs, s.File, s.ContentType, s.Package); err != nil {
		return err
	}
	if err := texts(MaxText, s.Script, s.Body, s.Headers); err != nil {
		return err
	}
	if err := s.When.validate("conditions"); err != nil {
		return err
	}
	if s.TimeoutSeconds < 0 || s.TimeoutSeconds > 4*3600 {
		return errors.New("timeout must be between 0 and 4 hours")
	}
	if s.Package != "" && !isSHA256(s.Package) {
		return errors.New("invalid package")
	}
	if s.SHA256 != "" && !isSHA256(s.SHA256) {
		return errors.New("the SHA-256 must be 64 hexadecimal characters")
	}
	s.Package, s.SHA256 = strings.ToLower(s.Package), strings.ToLower(s.SHA256)
	switch s.Type {
	case StepScript:
		if strings.TrimSpace(s.Script) == "" {
			return errors.New("script is required")
		}
	case StepCommand:
		if strings.TrimSpace(s.Command) == "" {
			return errors.New("command is required")
		}
	case StepDownload:
		if (s.Package == "") == (s.URL == "") {
			return errors.New("give either a library package or a URL")
		}
		if s.URL != "" {
			if err := checkURL(s.URL); err != nil {
				return err
			}
		}
		if s.Package == "" && strings.TrimSpace(s.SaveAs) == "" {
			return errors.New("a download from a URL needs the file name to save as")
		}
	case StepHTTP:
		if err := checkURL(s.URL); err != nil {
			return err
		}
		s.Method = strings.ToUpper(s.Method)
		if s.Method == "" {
			s.Method = "GET"
		}
		if s.Method != "GET" && s.Method != "POST" {
			return errors.New("method must be GET or POST")
		}
		for _, line := range strings.Split(strings.ReplaceAll(s.Headers, "\r", ""), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			if k, _, ok := strings.Cut(line, ":"); !ok || strings.TrimSpace(k) == "" || strings.ContainsAny(k, " \t") {
				return fmt.Errorf("header %q is not Name: value", line)
			}
		}
	case StepInstall:
		if (s.Package == "") == (strings.TrimSpace(s.File) == "") {
			return errors.New("give either a library package or a downloaded file")
		}
		if !slices.Contains(InstallKinds, s.Kind) {
			return fmt.Errorf("unknown installer kind %q", s.Kind)
		}
	default:
		return fmt.Errorf("unknown step type %q", s.Type)
	}
	return nil
}

func checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("the URL must be http:// or https://")
	}
	return nil
}

func isSHA256(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32
}

// Packages returns the library packages the steps use, by SHA-256 (hex,
// lower case), in order of first use.
func (d *Document) Packages() []string {
	var out []string
	for _, s := range d.Steps {
		if s.Package != "" && !slices.Contains(out, s.Package) {
			out = append(out, s.Package)
		}
	}
	return out
}

// Params is the job parameters of a revision: the document with the
// workflow's identity, for the job list and the deployment status.
type Params struct {
	WorkflowID string   `json:"workflow_id"`
	Name       string   `json:"name"`
	Revision   int      `json:"revision"`
	Workflow   Document `json:"workflow"`
}

// Result is what the module reports.
type Result struct {
	// Compliant: the detection rules held before the steps; nothing ran.
	Compliant bool         `json:"compliant"`
	Verified  bool         `json:"verified"` // detection held after the steps
	Steps     []StepResult `json:"steps"`
	// RebootRequired: an installer asked for a reboot (recorded for the
	// reboot module).
	RebootRequired bool `json:"reboot_required"`
}

// StepResult is the outcome of a step.
type StepResult struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Status   string `json:"status"` // ok | skipped | failed
	Detail   string `json:"detail,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"`
}
