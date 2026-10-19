// Package authn verifies operator identities issued by Microsoft Entra ID
// (or any OIDC provider with the same claims, used in tests).
//
// Both the console and the signer use it. The signer in particular relies on
// it to decide, independently of the console, whether a job was approved by
// an authorized operator with multi-factor authentication.
package authn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/stefanozanarini/open-rmm/internal/ids"
)

// Roles are Entra app roles assigned to operators (or to groups of them).
const (
	RoleAdmin    = "OpenRMM.Admin"
	RoleOperator = "OpenRMM.Operator"
	RoleReader   = "OpenRMM.Reader"
)

// Config describes the identity provider and the policy applied to tokens.
type Config struct {
	// Issuer, e.g. https://login.microsoftonline.com/<tenant-id>/v2.0
	Issuer   string
	ClientID string
	// MFAClaim selects how MFA is proven:
	//   "amr"         the amr claim must contain "mfa"
	//   "acrs:<id>"   the acrs claim must contain the Conditional Access
	//                 authentication context <id> (e.g. "acrs:c1")
	MFAClaim string
	// TenantMap maps the Entra tenant (tid claim) to the open-rmm tenants
	// its operators may manage.
	TenantMap map[string][]string
	// MaxAuthAge bounds how old an authentication may be when it approves a
	// job (step-up).
	MaxAuthAge time.Duration
	// MaxRole, when set, caps the roles taken from tokens: a customer
	// console may delegate less than Admin to a central console's operators.
	MaxRole string
}

// FromEnv reads the shared configuration:
//
//	OPENRMM_OIDC_ISSUER     https://login.microsoftonline.com/<tid>/v2.0
//	OPENRMM_OIDC_CLIENT_ID  application (client) ID
//	OPENRMM_MFA_CLAIM       "amr" (default) or "acrs:<context id>"
//	OPENRMM_TENANT_MAP      <entra tid>=<open-rmm tenant>[|<tenant>...][,...]
func FromEnv() (Config, error) {
	c := Config{
		Issuer:     os.Getenv("OPENRMM_OIDC_ISSUER"),
		ClientID:   os.Getenv("OPENRMM_OIDC_CLIENT_ID"),
		MFAClaim:   os.Getenv("OPENRMM_MFA_CLAIM"),
		MaxAuthAge: 10 * time.Minute,
	}
	if c.MFAClaim == "" {
		c.MFAClaim = "amr"
	}
	m, err := ParseTenantMap(os.Getenv("OPENRMM_TENANT_MAP"))
	if err != nil {
		return c, err
	}
	c.TenantMap = m
	return c, c.Validate()
}

// FederationFromEnv reads the identity provider of a central console whose
// operators may manage this console through a federation link. ok is false
// when it is not configured. The tenant map names the local tenant(s) the
// central directory may manage; MaxRole defaults to Admin.
//
//	OPENRMM_FEDERATION_ISSUER, OPENRMM_FEDERATION_CLIENT_ID
//	OPENRMM_FEDERATION_MFA_CLAIM    as OPENRMM_MFA_CLAIM, default "amr"
//	OPENRMM_FEDERATION_TENANT_MAP   <central entra tid>=<local tenant>
//	OPENRMM_FEDERATION_MAX_ROLE     OpenRMM.Admin | OpenRMM.Operator | OpenRMM.Reader
func FederationFromEnv() (c Config, ok bool, err error) {
	c = Config{
		Issuer:     os.Getenv("OPENRMM_FEDERATION_ISSUER"),
		ClientID:   os.Getenv("OPENRMM_FEDERATION_CLIENT_ID"),
		MFAClaim:   os.Getenv("OPENRMM_FEDERATION_MFA_CLAIM"),
		MaxRole:    os.Getenv("OPENRMM_FEDERATION_MAX_ROLE"),
		MaxAuthAge: 10 * time.Minute,
	}
	if c.Issuer == "" {
		return c, false, nil
	}
	if c.MFAClaim == "" {
		c.MFAClaim = "amr"
	}
	if c.MaxRole == "" {
		c.MaxRole = RoleAdmin
	}
	if c.TenantMap, err = ParseTenantMap(os.Getenv("OPENRMM_FEDERATION_TENANT_MAP")); err != nil {
		return c, false, fmt.Errorf("federation: %w", err)
	}
	if err := c.Validate(); err != nil {
		return c, false, fmt.Errorf("federation: %w", err)
	}
	return c, true, nil
}

// roleRank orders the roles.
var roleRank = map[string]int{RoleReader: 1, RoleOperator: 2, RoleAdmin: 3}

// capRoles lowers roles above max to max.
func capRoles(roles []string, max string) []string {
	var out []string
	for _, r := range roles {
		if roleRank[r] > roleRank[max] {
			r = max
		}
		if !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	return out
}

// IssuerOf returns the unverified iss claim of a JWT, to pick the verifier
// that will verify it.
func IssuerOf(rawIDToken string) string {
	parts := strings.Split(rawIDToken, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		Issuer string `json:"iss"`
	}
	if json.Unmarshal(payload, &c) != nil {
		return ""
	}
	return c.Issuer
}

// ParseTenantMap parses "tid=t1|t2,tid2=t3".
func ParseTenantMap(s string) (map[string][]string, error) {
	out := map[string][]string{}
	for _, entry := range strings.Split(s, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		tid, tenants, ok := strings.Cut(entry, "=")
		if !ok || !ids.IsUUID(tid) {
			return nil, fmt.Errorf("tenant map: invalid entry %q", entry)
		}
		for _, t := range strings.Split(tenants, "|") {
			if !ids.IsUUID(t) {
				return nil, fmt.Errorf("tenant map: invalid tenant %q", t)
			}
			out[tid] = append(out[tid], t)
		}
	}
	return out, nil
}

func (c Config) Validate() error {
	if !strings.HasPrefix(c.Issuer, "https://") && !strings.HasPrefix(c.Issuer, "http://127.0.0.1") {
		return errors.New("OPENRMM_OIDC_ISSUER must be an https URL")
	}
	if c.ClientID == "" {
		return errors.New("OPENRMM_OIDC_CLIENT_ID is required")
	}
	if c.MFAClaim != "amr" && !strings.HasPrefix(c.MFAClaim, "acrs:") {
		return errors.New(`OPENRMM_MFA_CLAIM must be "amr" or "acrs:<context id>"`)
	}
	if len(c.TenantMap) == 0 {
		return errors.New("OPENRMM_TENANT_MAP is required")
	}
	if _, ok := roleRank[c.MaxRole]; c.MaxRole != "" && !ok {
		return fmt.Errorf("invalid maximum role %q", c.MaxRole)
	}
	return nil
}

// Claims are the token claims open-rmm uses.
type Claims struct {
	Subject  string   `json:"sub"`
	ObjectID string   `json:"oid"`
	TenantID string   `json:"tid"`
	Name     string   `json:"name"`
	Username string   `json:"preferred_username"`
	Roles    []string `json:"roles"`
	AMR      []string `json:"amr"`
	ACRS     []string `json:"acrs"`
	Nonce    string   `json:"nonce"`
	AuthTime int64    `json:"auth_time"`
	IssuedAt int64    `json:"iat"`
}

// Operator returns a stable, readable identity for audit logs.
func (c *Claims) Operator() string {
	who := c.Username
	if who == "" {
		who = c.Name
	}
	return fmt.Sprintf("%s (oid %s)", who, c.ObjectID)
}

// HasRole reports whether the operator has any of roles.
func (c *Claims) HasRole(roles ...string) bool {
	for _, r := range roles {
		if slices.Contains(c.Roles, r) {
			return true
		}
	}
	return false
}

// Verifier validates id_tokens.
type Verifier struct {
	cfg      Config
	verifier *oidc.IDTokenVerifier
	Provider *oidc.Provider
}

// NewVerifier discovers the provider. ctx may carry an *http.Client (see
// oidc.ClientContext) for tests.
func NewVerifier(ctx context.Context, cfg Config) (*Verifier, error) {
	p, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery: %w", err)
	}
	return &Verifier{cfg: cfg, Provider: p, verifier: p.Verifier(&oidc.Config{
		ClientID:             cfg.ClientID,
		SupportedSigningAlgs: []string{oidc.RS256},
	})}, nil
}

var (
	ErrNoMFA      = errors.New("the authentication did not use multi-factor authentication")
	ErrStale      = errors.New("the authentication is too old: sign in again")
	ErrNonce      = errors.New("the authentication was not issued for this request")
	ErrNoTenant   = errors.New("the operator's directory is not allowed on this console")
	ErrNoRole     = errors.New("the operator has no open-rmm role")
	ErrMissingOID = errors.New("token without object id")
)

// Verify checks signature, issuer, audience and expiry, then extracts the
// claims and checks that the operator belongs to an allowed directory and has
// at least one open-rmm role. MFA is always required.
func (v *Verifier) Verify(ctx context.Context, rawIDToken string) (*Claims, error) {
	tok, err := v.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}
	var c Claims
	if err := tok.Claims(&c); err != nil {
		return nil, err
	}
	if c.ObjectID == "" {
		return nil, ErrMissingOID
	}
	if _, ok := v.cfg.TenantMap[c.TenantID]; !ok {
		return nil, ErrNoTenant
	}
	if v.cfg.MaxRole != "" {
		c.Roles = capRoles(c.Roles, v.cfg.MaxRole)
	}
	if !c.HasRole(RoleAdmin, RoleOperator, RoleReader) {
		return nil, ErrNoRole
	}
	if err := v.checkMFA(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (v *Verifier) checkMFA(c *Claims) error {
	// The claims seen are included in the error: when setting up a new
	// directory they show at once which claim the provider actually sends.
	if ctxID, ok := strings.CutPrefix(v.cfg.MFAClaim, "acrs:"); ok {
		if !slices.Contains(c.ACRS, ctxID) {
			return fmt.Errorf("%w (acrs=%v, expected %q)", ErrNoMFA, c.ACRS, ctxID)
		}
		return nil
	}
	if !slices.Contains(c.AMR, "mfa") {
		return fmt.Errorf("%w (amr=%v)", ErrNoMFA, c.AMR)
	}
	return nil
}

// CheckFresh verifies that the authentication happened recently. auth_time
// is used when present, otherwise the issue time.
func (v *Verifier) CheckFresh(c *Claims, now time.Time) error {
	at := c.AuthTime
	if at == 0 {
		at = c.IssuedAt
	}
	t := time.Unix(at, 0)
	if now.Sub(t) > v.cfg.MaxAuthAge || t.After(now.Add(2*time.Minute)) {
		return ErrStale
	}
	return nil
}

// Tenants returns the open-rmm tenants the operator may manage.
func (v *Verifier) Tenants(c *Claims) []string { return v.cfg.TenantMap[c.TenantID] }

// MayManage reports whether the operator may act on tenantID.
func (v *Verifier) MayManage(c *Claims, tenantID string) bool {
	return slices.Contains(v.cfg.TenantMap[c.TenantID], tenantID)
}

// Config returns the configuration.
func (v *Verifier) Config() Config { return v.cfg }

// Set picks, among several verifiers, the one for a token's issuer: the
// console's own directory and, with federation, the central console's.
type Set []*Verifier

// For returns the verifier of the token's issuer, or nil.
func (s Set) For(rawIDToken string) *Verifier {
	iss := IssuerOf(rawIDToken)
	for _, v := range s {
		if v != nil && iss != "" && v.cfg.Issuer == iss {
			return v
		}
	}
	return nil
}

// CapRoles applies the configured maximum role to roles asserted by a
// central console (the same cap Verify applies to tokens).
func (v *Verifier) CapRoles(roles []string) []string {
	if v.cfg.MaxRole == "" {
		return roles
	}
	return capRoles(roles, v.cfg.MaxRole)
}
