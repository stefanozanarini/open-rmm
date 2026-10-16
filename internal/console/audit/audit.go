// Package audit defines audit events and their hash chain.
package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Event is one audit log entry.
type Event struct {
	TenantID   string
	Seq        int64
	OccurredAt time.Time
	Actor      string // e.g. "agent:<id>", "operator:<upn>", "system"
	Action     string // e.g. "agent.enrolled"
	Target     string
	Details    map[string]any
	PrevHash   []byte
	Hash       []byte
}

// GenesisHash is the prev_hash of the first event of every tenant.
var GenesisHash = make([]byte, sha256.Size)

// ComputeHash returns SHA-256(prev_hash || canonical(event)). Every field is
// length-prefixed so that no two different events share an encoding.
func ComputeHash(e Event) ([]byte, error) {
	if e.Seq < 1 {
		return nil, fmt.Errorf("audit seq must be positive, got %d", e.Seq)
	}
	details, err := canonicalDetails(e.Details)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.Write(e.PrevHash)
	writeField := func(b []byte) {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(b)))
		buf.Write(l[:])
		buf.Write(b)
	}
	writeField([]byte(e.TenantID))
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], uint64(e.Seq)) // #nosec G115 -- checked positive above
	writeField(seq[:])
	writeField([]byte(e.OccurredAt.UTC().Format(time.RFC3339Nano)))
	writeField([]byte(e.Actor))
	writeField([]byte(e.Action))
	writeField([]byte(e.Target))
	writeField(details)
	sum := sha256.Sum256(buf.Bytes())
	return sum[:], nil
}

// canonicalDetails encodes details as JSON. encoding/json sorts map keys, so
// the output is deterministic for the same map.
func canonicalDetails(d map[string]any) ([]byte, error) {
	if d == nil {
		d = map[string]any{}
	}
	b, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("audit details: %w", err)
	}
	return b, nil
}

// VerifyChain checks that events (ordered by Seq, starting at 1) form an
// unbroken chain.
func VerifyChain(events []Event) error {
	prev := GenesisHash
	for i, e := range events {
		if e.Seq != int64(i+1) {
			return fmt.Errorf("event %d: unexpected seq %d", i+1, e.Seq)
		}
		if !bytes.Equal(e.PrevHash, prev) {
			return fmt.Errorf("event %d: prev_hash mismatch", e.Seq)
		}
		h, err := ComputeHash(e)
		if err != nil {
			return err
		}
		if !bytes.Equal(h, e.Hash) {
			return fmt.Errorf("event %d: hash mismatch", e.Seq)
		}
		prev = e.Hash
	}
	return nil
}

// ErrEmptyAction is returned for events without an action.
var ErrEmptyAction = errors.New("audit event needs an action")
