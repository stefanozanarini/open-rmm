package policies

import (
	"github.com/stefanozanarini/open-rmm/internal/policy"
)

// Probe answers the elementary questions conditions ask about the endpoint.
// The platform implementation is in probe_*.go; tests use a fake.
type Probe interface {
	ServiceExists(name string) bool
	FileExists(path string) bool
	RegistryKeyExists(path string) bool
	OSFamily() string
}

// Eval evaluates a condition; a nil condition is true.
func Eval(c *policy.Condition, p Probe) bool {
	if c == nil {
		return true
	}
	switch {
	case c.ServiceExists != "":
		return p.ServiceExists(c.ServiceExists)
	case c.FileExists != "":
		return p.FileExists(c.FileExists)
	case c.RegistryKeyExists != "":
		return p.RegistryKeyExists(c.RegistryKeyExists)
	case c.OSFamily != "":
		return p.OSFamily() == c.OSFamily
	case len(c.All) > 0:
		for i := range c.All {
			if !Eval(&c.All[i], p) {
				return false
			}
		}
		return true
	case len(c.Any) > 0:
		for i := range c.Any {
			if Eval(&c.Any[i], p) {
				return true
			}
		}
		return false
	case c.Not != nil:
		return !Eval(c.Not, p)
	}
	return false
}
