package assignreq

import (
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	openrmmv1 "github.com/stefanozanarini/tempra-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
)

func sample(now time.Time) *openrmmv1.AssignmentRequest {
	sum := sha256.Sum256([]byte("manifest"))
	return &openrmmv1.AssignmentRequest{
		TenantId: ids.NewUUID(), WorkflowId: ids.NewUUID(), GroupId: ids.NewUUID(), Revision: 3,
		Module: "workflow", ModuleVersion: "1.0.0", ModuleSha256: sum[:], Action: "run",
		ParamsJson: []byte(`{"a":1}`), MaxTtlSeconds: int64((24 * time.Hour).Seconds()),
		ExpiresUnix: now.Add(90 * 24 * time.Hour).Unix(), RequestNonce: NewRequestNonce(),
	}
}

func TestValidate(t *testing.T) {
	now := time.Now()
	if err := Validate(sample(now), now); err != nil {
		t.Fatal(err)
	}
	bad := sample(now)
	bad.TenantId = "not-a-uuid"
	if Validate(bad, now) == nil {
		t.Error("invalid tenant accepted")
	}
	bad = sample(now)
	bad.GroupId = ""
	if Validate(bad, now) == nil {
		t.Error("missing group accepted")
	}
	bad = sample(now)
	bad.Revision = 0
	if Validate(bad, now) == nil {
		t.Error("zero revision accepted")
	}
	bad = sample(now)
	bad.MaxTtlSeconds = 10 // below MinTTL
	if Validate(bad, now) == nil {
		t.Error("ttl below minimum accepted")
	}
	bad = sample(now)
	bad.ExpiresUnix = now.Add(time.Hour).Unix() // below MinValidity
	if Validate(bad, now) == nil {
		t.Error("validity below minimum accepted")
	}
	bad = sample(now)
	bad.ExpiresUnix = now.Add(2 * MaxValidity).Unix()
	if Validate(bad, now) == nil {
		t.Error("validity beyond maximum accepted")
	}
	bad = sample(now)
	bad.ParamsJson = []byte("not json")
	if Validate(bad, now) == nil {
		t.Error("invalid params accepted")
	}
	bad = sample(now)
	bad.RequestNonce = []byte("short")
	if Validate(bad, now) == nil {
		t.Error("short nonce accepted")
	}
}

func TestHashAndNonce(t *testing.T) {
	now := time.Now()
	a, b := sample(now), sample(now)
	if string(Hash(a)) == string(Hash(b)) {
		t.Fatal("two distinct assignments hash the same")
	}
	if !CheckAuthNonce(AuthNonce(a), a) {
		t.Fatal("own nonce not accepted")
	}
	if CheckAuthNonce(AuthNonce(a), b) {
		t.Fatal("nonce accepted for another assignment")
	}
	if !strings.HasPrefix(AuthNonce(a), "assignment.") {
		t.Fatalf("nonce = %q", AuthNonce(a))
	}
	// Changing any field must change the hash (binding every field, not
	// just the ones checked above).
	for name, mutate := range map[string]func(*openrmmv1.AssignmentRequest){
		"group":          func(r *openrmmv1.AssignmentRequest) { r.GroupId = ids.NewUUID() },
		"revision":       func(r *openrmmv1.AssignmentRequest) { r.Revision++ },
		"module_version": func(r *openrmmv1.AssignmentRequest) { r.ModuleVersion = "2.0.0" },
		"action":         func(r *openrmmv1.AssignmentRequest) { r.Action = "other" },
		"params":         func(r *openrmmv1.AssignmentRequest) { r.ParamsJson = []byte(`{"a":2}`) },
		"max_ttl":        func(r *openrmmv1.AssignmentRequest) { r.MaxTtlSeconds++ },
		"expires":        func(r *openrmmv1.AssignmentRequest) { r.ExpiresUnix++ },
		"packages": func(r *openrmmv1.AssignmentRequest) {
			r.Packages = []*openrmmv1.PackageRef{{Sha256: make([]byte, 32), FileName: "x.msi", Size: 1}}
		},
	} {
		c := sample(now)
		mutate(c)
		if string(Hash(a)) == string(Hash(c)) {
			t.Errorf("%s: hash unchanged", name)
		}
	}
}

func TestValidateTargets(t *testing.T) {
	if err := ValidateTargets([]string{ids.NewUUID()}, 5); err != nil {
		t.Fatal(err)
	}
	if ValidateTargets(nil, 5) == nil {
		t.Error("empty targets accepted")
	}
	if ValidateTargets([]string{"x"}, 5) == nil {
		t.Error("non-UUID target accepted")
	}
	id := ids.NewUUID()
	if ValidateTargets([]string{id, id}, 5) == nil {
		t.Error("duplicate target accepted")
	}
	var many []string
	for i := 0; i < 6; i++ {
		many = append(many, ids.NewUUID())
	}
	if ValidateTargets(many, 5) == nil {
		t.Error("too many targets accepted")
	}
}
