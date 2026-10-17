package e2e

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/console/authn"
	"github.com/stefanozanarini/open-rmm/internal/console/jobreq"
	"github.com/stefanozanarini/open-rmm/internal/console/signer"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/console/web"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/modules"
	"github.com/stefanozanarini/open-rmm/internal/signing"
)

// opIdentity is who the fake identity provider signs in.
type opIdentity struct {
	OID, Name, Username string
	Roles, AMR          []string
}

// fakeIdP is a minimal OIDC provider: discovery, JWKS, authorize (signs the
// configured identity in at once) and token with PKCE.
type fakeIdP struct {
	srv      *httptest.Server
	key      *rsa.PrivateKey
	tid      string
	clientID string

	mu       sync.Mutex
	user     opIdentity
	codes    map[string]authReq
	lastAuth url.Values
	issued   []string // raw id_tokens
}

type authReq struct {
	nonce, challenge, redirect string
}

func newIdP(t *testing.T, tid, clientID string) *fakeIdP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeIdP{key: key, tid: tid, clientID: clientID, codes: map[string]authReq{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": p.srv.URL, "authorization_endpoint": p.srv.URL + "/authorize",
			"token_endpoint": p.srv.URL + "/token", "jwks_uri": p.srv.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("client_id") != clientID || q.Get("code_challenge_method") != "S256" {
			http.Error(w, "bad request", 400)
			return
		}
		code := ids.NewSecret(16)
		p.mu.Lock()
		p.codes[code] = authReq{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri")}
		p.lastAuth = q
		p.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		p.mu.Lock()
		req, ok := p.codes[r.PostForm.Get("code")]
		delete(p.codes, r.PostForm.Get("code"))
		user := p.user
		p.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != req.challenge {
			http.Error(w, `{"error":"invalid_grant"}`, 400)
			return
		}
		now := time.Now()
		sig, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
		raw, _ := jwt.Signed(sig).Claims(map[string]any{
			"iss": p.srv.URL, "aud": clientID, "sub": "sub-" + user.OID, "oid": user.OID, "tid": tid,
			"name": user.Name, "preferred_username": user.Username, "roles": user.Roles, "amr": user.AMR,
			"nonce": req.nonce, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "auth_time": now.Unix(),
		}).Serialize()
		p.mu.Lock()
		p.issued = append(p.issued, raw)
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "x", "token_type": "Bearer", "id_token": raw, "expires_in": 3600})
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeIdP) signIn(u opIdentity) {
	p.mu.Lock()
	p.user = u
	p.mu.Unlock()
}

type consoleEnv struct {
	store   *store.Memory
	idp     *fakeIdP
	console *httptest.Server
	signer  openrmmv1.SignerServiceClient
	jobKeys *signing.Keyring
	tenant  string
	agentID string
	module  *modules.Verified
}

var admin = opIdentity{OID: ids.NewUUID(), Name: "Mario Rossi", Username: "mario@cliente.it",
	Roles: []string{authn.RoleAdmin}, AMR: []string{"pwd", "mfa"}}

func startConsole(t *testing.T) *consoleEnv {
	t.Helper()
	ctx := context.Background()
	tid, clientID := ids.NewUUID(), "console-app"
	idp := newIdP(t, tid, clientID)
	st := store.NewMemory()
	tenant := ids.NewUUID()
	st.CreateTenant(ctx, store.Tenant{ID: tenant, Name: "Cliente"})
	cfg := authn.Config{Issuer: idp.srv.URL, ClientID: clientID, MFAClaim: "amr",
		TenantMap: map[string][]string{tid: {tenant}}, MaxAuthAge: 10 * time.Minute}
	v, err := authn.NewVerifier(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Signer on a Unix socket, as in production.
	jobSigner := newSigner(t)
	sockDir, _ := os.MkdirTemp("", "sg")
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "s.sock")
	sgv, _ := authn.NewVerifier(ctx, cfg)
	sg, err := signer.New(jobSigner, sgv, filepath.Join(sockDir, "used.json"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	openrmmv1.RegisterSignerServiceServer(gs, sg)
	go gs.Serve(lis)
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	sc := openrmmv1.NewSignerServiceClient(conn)

	console := httptest.NewUnstartedServer(nil)
	console.StartTLS()
	t.Cleanup(console.Close)
	ws, err := web.New(web.Config{Store: st, Verifier: v, Signer: sc, PublicURL: console.URL, ClientSecret: "secret",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), HTTPClient: http.DefaultClient})
	if err != nil {
		t.Fatal(err)
	}
	console.Config.Handler = ws.Handler()

	// A pending Linux agent and a published module that supports it.
	agentID := ids.NewUUID()
	st.CreateAgent(ctx, store.Agent{TenantID: tenant, ID: agentID, Status: store.AgentPending,
		Host:            store.HostInfo{Hostname: "pc01", OS: "linux", Arch: "amd64", OSVersion: "Ubuntu"},
		CertFingerprint: "fp", CertNotAfter: time.Now().Add(time.Hour)})
	e := &consoleEnv{store: st, idp: idp, console: console, signer: sc, tenant: tenant, agentID: agentID}
	e.jobKeys = signing.NewKeyring()
	pub, _ := signing.ParsePublicKey(pubKey(jobSigner))
	e.jobKeys.Add(pub, signing.DomainJob)
	e.module = publishTo(t, st, filepath.Join(repoRoot(t), "modules", "sysinfo"))
	return e
}

// publishTo signs and stores a module with a throwaway release key.
func publishTo(t *testing.T, st store.Store, dir string) *modules.Verified {
	t.Helper()
	raw, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
	var m modules.Manifest
	json.Unmarshal(raw, &m)
	sdk, _ := os.ReadFile(filepath.Join(repoRoot(t), "modules", "sdk", "sh", "openrmm.sh"))
	psdk, _ := os.ReadFile(filepath.Join(repoRoot(t), "modules", "sdk", "powershell", "OpenRmm.psm1"))
	archive, err := modules.Pack(&m, dir, map[string][]byte{"_sdk/openrmm.sh": sdk, "_sdk/OpenRmm.psm1": psdk})
	if err != nil {
		t.Fatal(err)
	}
	ms := newSigner(t)
	b, _ := modules.SignBundle(ms, &m, archive)
	keys := signing.NewKeyring()
	pub, _ := signing.ParsePublicKey(pubKey(ms))
	keys.Add(pub, signing.DomainModuleManifest)
	v, err := b.Verify(keys)
	if err != nil {
		t.Fatal(err)
	}
	st.PutModule(context.Background(), store.Module{ID: m.ID, Version: m.Version, KeyID: b.KeyID, Manifest: b.Manifest,
		Signature: b.Signature, ManifestSHA256: v.ManifestHash, Archive: b.Archive})
	return v
}

// browser is an HTTP client with cookies that follows redirects.
func (e *consoleEnv) browser(t *testing.T) *http.Client {
	jar, _ := cookiejar.New(nil)
	c := e.console.Client()
	c.Jar = jar
	return c
}

func get(t *testing.T, c *http.Client, u string) (int, string) {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func post(t *testing.T, c *http.Client, u string, form url.Values) (int, string, *url.URL) {
	t.Helper()
	resp, err := c.PostForm(u, form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Request.URL
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func csrfFrom(t *testing.T, body string) string {
	t.Helper()
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no CSRF token in page")
	}
	return html.UnescapeString(m[1])
}

func (e *consoleEnv) login(t *testing.T, u opIdentity) (*http.Client, string) {
	t.Helper()
	e.idp.signIn(u)
	c := e.browser(t)
	code, body := get(t, c, e.console.URL+"/agents")
	if code != 200 || !strings.Contains(body, "pc01") {
		t.Fatalf("login: %d %s", code, body)
	}
	return c, csrfFrom(t, body)
}

func TestConsoleApproveAndRunJobWithStepUp(t *testing.T) {
	e := startConsole(t)
	c, csrf := e.login(t, admin)
	agentURL := e.console.URL + "/agents/" + e.agentID

	if code, _, _ := post(t, c, agentURL+"/approve", url.Values{"csrf": {csrf}}); code != 200 {
		t.Fatalf("approve: %d", code)
	}
	if a, _ := e.store.GetAgent(context.Background(), e.tenant, e.agentID); a.Status != store.AgentActive || !strings.Contains(a.ApprovedBy, admin.Username) {
		t.Fatalf("agent after approval: %s by %q", a.Status, a.ApprovedBy)
	}

	target := "sysinfo|1.0.0|info"
	code, body, final := post(t, c, agentURL+"/jobs", url.Values{"csrf": {csrf}, "target": {target}, "params": {"{}"}, "ttl_minutes": {"60"}})
	if code != 200 || !strings.HasPrefix(final.Path, "/jobs/") {
		t.Fatalf("run job: %d at %s: %s", code, final, body)
	}
	// The step-up forced a new sign-in.
	e.idp.mu.Lock()
	auth := e.idp.lastAuth
	e.idp.mu.Unlock()
	if auth.Get("prompt") != "login" || auth.Get("max_age") != "0" || !strings.HasPrefix(auth.Get("nonce"), "job.") {
		t.Fatalf("step-up authorize params: %v", auth)
	}

	jobID := strings.TrimPrefix(final.Path, "/jobs/")
	j, err := e.store.GetJob(context.Background(), e.tenant, jobID)
	if err != nil {
		t.Fatal(err)
	}
	if j.State != store.JobQueued || !strings.Contains(j.CreatedBy, admin.Username) {
		t.Fatalf("job = %+v", j)
	}
	// The envelope is signed by the signer's key and carries what was approved.
	env := &openrmmv1.SignedEnvelope{}
	proto.Unmarshal(j.Envelope, env)
	if err := e.jobKeys.Verify(signing.DomainJob, env.GetKeyId(), env.GetPayload(), env.GetSignature()); err != nil {
		t.Fatalf("envelope signature: %v", err)
	}
	job := &openrmmv1.Job{}
	proto.Unmarshal(env.GetPayload(), job)
	if job.GetAgentId() != e.agentID || job.GetModule() != "sysinfo" || string(job.GetModuleSha256()) != string(e.module.ManifestHash) {
		t.Fatalf("signed job = %+v", job)
	}

	events, _ := e.store.ListAudit(context.Background(), e.tenant)
	var actions []string
	for _, ev := range events {
		actions = append(actions, ev.Action)
	}
	if got := strings.Join(actions, ","); !strings.Contains(got, "operator.login,agent.approved,job.created") {
		t.Fatalf("audit = %s", got)
	}
}

func TestConsoleRequiresMFA(t *testing.T) {
	e := startConsole(t)
	noMFA := admin
	noMFA.AMR = []string{"pwd"}
	e.idp.signIn(noMFA)
	code, body := get(t, e.browser(t), e.console.URL+"/agents")
	if code != http.StatusForbidden || !strings.Contains(body, "più fattori") {
		t.Fatalf("login without MFA: %d %s", code, body)
	}
}

func TestConsoleRequiresRole(t *testing.T) {
	e := startConsole(t)
	noRole := admin
	noRole.Roles = nil
	e.idp.signIn(noRole)
	if code, _ := get(t, e.browser(t), e.console.URL+"/agents"); code != http.StatusForbidden {
		t.Fatalf("login without role: %d", code)
	}
}

func TestReaderCannotApproveOrRun(t *testing.T) {
	e := startConsole(t)
	reader := admin
	reader.OID, reader.Roles = ids.NewUUID(), []string{authn.RoleReader}
	c, csrf := e.login(t, reader)
	agentURL := e.console.URL + "/agents/" + e.agentID
	if code, _, _ := post(t, c, agentURL+"/approve", url.Values{"csrf": {csrf}}); code != http.StatusForbidden {
		t.Fatalf("reader approve: %d", code)
	}
	if code, _, _ := post(t, c, agentURL+"/jobs", url.Values{"csrf": {csrf}, "target": {"sysinfo|1.0.0|info"}}); code != http.StatusForbidden {
		t.Fatalf("reader run: %d", code)
	}
}

func TestCSRFIsRequired(t *testing.T) {
	e := startConsole(t)
	c, _ := e.login(t, admin)
	if code, _, _ := post(t, c, e.console.URL+"/agents/"+e.agentID+"/approve", url.Values{}); code != http.StatusForbidden {
		t.Fatalf("approve without CSRF token: %d", code)
	}
	if a, _ := e.store.GetAgent(context.Background(), e.tenant, e.agentID); a.Status != store.AgentPending {
		t.Fatal("agent approved without CSRF token")
	}
}

func TestStepUpByAnotherOperatorIsRefused(t *testing.T) {
	e := startConsole(t)
	e.store.ApproveAgent(context.Background(), e.tenant, e.agentID, "t", time.Now())
	c, csrf := e.login(t, admin)
	other := admin
	other.OID, other.Username = ids.NewUUID(), "luigi@cliente.it"
	e.idp.signIn(other) // someone else completes the step-up
	code, _, _ := post(t, c, e.console.URL+"/agents/"+e.agentID+"/jobs",
		url.Values{"csrf": {csrf}, "target": {"sysinfo|1.0.0|info"}, "ttl_minutes": {"60"}})
	if code != http.StatusForbidden {
		t.Fatalf("step-up by another operator: %d", code)
	}
	if jobs, _ := e.store.ListJobs(context.Background(), e.tenant, "", 10); len(jobs) != 0 {
		t.Fatal("job created")
	}
}

// The signer must not trust the console: these calls bypass it.
func TestSignerVerifiesIndependently(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	req := &openrmmv1.JobRequest{TenantId: e.tenant, AgentId: e.agentID, Module: "sysinfo", ModuleVersion: "1.0.0",
		ModuleSha256: e.module.ManifestHash, Action: "info", ParamsJson: []byte("{}"), TtlSeconds: 3600,
		RequestNonce: jobreq.NewRequestNonce()}
	token := e.tokenFor(t, admin, jobreq.AuthNonce(req))

	// A different request (here: other parameters) with that approval.
	tampered := proto.Clone(req).(*openrmmv1.JobRequest)
	tampered.ParamsJson = []byte(`{"evil":true}`)
	if _, err := e.signer.SignJob(ctx, &openrmmv1.SignJobRequest{Request: tampered, IdToken: token}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("tampered request: %v", err)
	}
	if _, err := e.signer.SignJob(ctx, &openrmmv1.SignJobRequest{Request: req, IdToken: token}); err != nil {
		t.Fatalf("legit request: %v", err)
	}
	// One approval, one job.
	if _, err := e.signer.SignJob(ctx, &openrmmv1.SignJobRequest{Request: req, IdToken: token}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("replayed approval: %v", err)
	}
	// Approval without MFA.
	noMFA := admin
	noMFA.AMR = []string{"pwd"}
	req2 := proto.Clone(req).(*openrmmv1.JobRequest)
	req2.RequestNonce = jobreq.NewRequestNonce()
	if _, err := e.signer.SignJob(ctx, &openrmmv1.SignJobRequest{Request: req2, IdToken: e.tokenFor(t, noMFA, jobreq.AuthNonce(req2))}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("approval without MFA: %v", err)
	}
	// Readers cannot approve jobs.
	reader := admin
	reader.Roles = []string{authn.RoleReader}
	req3 := proto.Clone(req).(*openrmmv1.JobRequest)
	req3.RequestNonce = jobreq.NewRequestNonce()
	if _, err := e.signer.SignJob(ctx, &openrmmv1.SignJobRequest{Request: req3, IdToken: e.tokenFor(t, reader, jobreq.AuthNonce(req3))}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("approval by a reader: %v", err)
	}
	// A tenant the operator's directory may not manage.
	req4 := proto.Clone(req).(*openrmmv1.JobRequest)
	req4.TenantId, req4.RequestNonce = ids.NewUUID(), jobreq.NewRequestNonce()
	if _, err := e.signer.SignJob(ctx, &openrmmv1.SignJobRequest{Request: req4, IdToken: e.tokenFor(t, admin, jobreq.AuthNonce(req4))}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("foreign tenant: %v", err)
	}
	// A token forged with another key.
	if _, err := e.signer.SignJob(ctx, &openrmmv1.SignJobRequest{Request: req, IdToken: forgedToken(t, e, jobreq.AuthNonce(req))}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("forged token: %v", err)
	}
}

// tokenFor runs the fake authorize+token round trip for nonce.
func (e *consoleEnv) tokenFor(t *testing.T, u opIdentity, nonce string) string {
	t.Helper()
	e.idp.signIn(u)
	verifier := ids.NewSecret(32)
	sum := sha256.Sum256([]byte(verifier))
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noRedirect.Get(e.idp.srv.URL + "/authorize?" + url.Values{"client_id": {"console-app"}, "nonce": {nonce},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		"redirect_uri": {"https://x/cb"}, "state": {"s"}}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	resp, err = http.PostForm(e.idp.srv.URL+"/token", url.Values{"code": {loc.Query().Get("code")}, "code_verifier": {verifier}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		IDToken string `json:"id_token"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	return out.IDToken
}

func forgedToken(t *testing.T, e *consoleEnv, nonce string) string {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	sig, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	now := time.Now()
	raw, _ := jwt.Signed(sig).Claims(map[string]any{"iss": e.idp.srv.URL, "aud": "console-app", "sub": "x", "oid": admin.OID,
		"tid": e.idp.tid, "roles": admin.Roles, "amr": admin.AMR, "nonce": nonce, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}).Serialize()
	return raw
}

func TestOriginHeaderChecked(t *testing.T) {
	e := startConsole(t)
	c, csrf := e.login(t, admin)
	do := func(origin string) int {
		req, _ := http.NewRequest(http.MethodPost, e.console.URL+"/agents/"+e.agentID+"/approve",
			strings.NewReader(url.Values{"csrf": {csrf}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", origin)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := do("https://evil.example"); code != http.StatusForbidden {
		t.Fatalf("foreign origin: %d", code)
	}
	if code := do("null"); code != http.StatusForbidden {
		t.Fatalf("null origin: %d", code)
	}
	// What a browser sends with Referrer-Policy: same-origin.
	if code := do(e.console.URL); code != http.StatusOK {
		t.Fatalf("own origin: %d", code)
	}
}
