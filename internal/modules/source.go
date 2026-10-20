package modules

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
)

// SDKFiles returns the SDK files a module needs, by archive path, read from
// src (the copy embedded in modules/sdk, or an SDK directory).
func SDKFiles(m *Manifest, src fs.FS) (map[string][]byte, error) {
	need := map[string]string{}
	for _, ep := range m.Entrypoints {
		switch ep.Type {
		case TypePowerShell:
			need["_sdk/OpenRmm.psm1"] = "powershell/OpenRmm.psm1"
		case TypeShell:
			need["_sdk/openrmm.sh"] = "sh/openrmm.sh"
		}
	}
	out := map[string][]byte{}
	for dst, p := range need {
		b, err := fs.ReadFile(src, p)
		if err != nil {
			return nil, fmt.Errorf("SDK: %w", err)
		}
		out[dst] = b
	}
	return out, nil
}

// ReadSource reads manifest.json of a module source tree, strictly: an
// unknown field is an error, not something silently dropped from what gets
// signed.
func ReadSource(src fs.FS) (*Manifest, error) {
	raw, err := fs.ReadFile(src, "manifest.json")
	if err != nil {
		return nil, err
	}
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest.json: %w", err)
	}
	return &m, nil
}

// SourceRoot returns the directory of src holding manifest.json: src itself,
// or its only top-level directory (a zip of the module folder).
func SourceRoot(src fs.FS) (fs.FS, error) {
	if _, err := fs.Stat(src, "manifest.json"); err == nil {
		return src, nil
	}
	entries, err := fs.ReadDir(src, ".")
	if err != nil {
		return nil, err
	}
	if len(entries) == 1 && entries[0].IsDir() {
		sub, err := fs.Sub(src, entries[0].Name())
		if err != nil {
			return nil, err
		}
		if _, err := fs.Stat(sub, "manifest.json"); err == nil {
			return sub, nil
		}
	}
	return nil, fmt.Errorf("manifest.json not found")
}

// SigningManifest returns the exact bytes SignBundle signs for m, for a
// signer that holds the key elsewhere (the console's builder).
func SigningManifest(m *Manifest) ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}
