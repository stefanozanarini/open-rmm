package modules

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

const (
	maxFileSize    = 64 << 20
	MaxArchiveSize = 64 << 20
	maxTotalSize   = 256 << 20
)

// Pack builds the archive from dir and fills in ArchiveSHA256 and Files.
// Every regular file under dir is included; symlinks and other special files
// are refused. extra adds files from outside dir (e.g. the SDK), keyed by
// their path in the archive.
func Pack(m *Manifest, dir string, extra map[string][]byte) ([]byte, error) {
	if err := m.Validate(false); err != nil {
		return nil, err
	}
	// Files are read through an os.Root, so a path swapped for a symlink
	// during the walk cannot make Pack read outside dir.
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	files := map[string][]byte{}
	err = fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s: only regular files can be packed", p)
		}
		if p == "manifest.json" {
			return nil
		}
		data, err := root.ReadFile(p)
		if err != nil {
			return err
		}
		files[p] = data
		return nil
	})
	if err != nil {
		return nil, err
	}
	for p, data := range extra {
		if _, dup := files[p]; dup {
			return nil, fmt.Errorf("%s exists in the module directory and in the SDK", p)
		}
		files[p] = data
	}
	names := make([]string, 0, len(files))
	for p := range files {
		names = append(names, p)
	}
	sort.Strings(names)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	m.Files = nil
	for _, p := range names {
		data := files[p]
		if err := validPath(p); err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		m.Files = append(m.Files, File{Path: p, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))})
		w, err := zw.CreateHeader(&zip.FileHeader{Name: p, Method: zip.Deflate})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(data); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	if buf.Len() > MaxArchiveSize {
		return nil, fmt.Errorf("archive too large (%d bytes)", buf.Len())
	}
	sum := sha256.Sum256(buf.Bytes())
	m.ArchiveSHA256 = hex.EncodeToString(sum[:])
	if err := m.Validate(true); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Extract verifies archive against m and writes its files under dest, which
// must not exist yet. Only the files listed in the manifest are accepted,
// each with exactly the declared size and hash.
func Extract(m *Manifest, archive []byte, dest string) error {
	if hexSHA256(archive) != m.ArchiveSHA256 {
		return errors.New("archive hash does not match the manifest")
	}
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return fmt.Errorf("archive: %w", err)
	}
	want := map[string]File{}
	for _, f := range m.Files {
		want[f.Path] = f
	}
	if len(zr.File) != len(want) {
		return errors.New("archive content does not match the manifest")
	}
	if _, err := os.Stat(dest); err == nil {
		return fmt.Errorf("%s already exists", dest)
	}
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return err
	}
	// Only native executables get the execute permission.
	exec := map[string]bool{}
	for _, ep := range m.Entrypoints {
		if ep.Type == TypeBinary {
			exec[ep.Path] = true
		}
	}
	var total int64
	done := map[string]bool{}
	for _, zf := range zr.File {
		f, ok := want[zf.Name]
		if !ok || done[zf.Name] {
			return fmt.Errorf("unexpected archive member %q", zf.Name)
		}
		done[zf.Name] = true
		if !zf.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file", zf.Name)
		}
		total += f.Size
		if total > maxTotalSize {
			return errors.New("archive expands beyond the size limit")
		}
		mode := os.FileMode(0o600)
		if exec[f.Path] {
			mode = 0o700
		}
		if err := extractFile(zf, f, filepath.Join(dest, filepath.FromSlash(f.Path)), mode); err != nil {
			return err
		}
	}
	return nil
}

func extractFile(zf *zip.File, f File, target string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	rc, err := zf.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) // #nosec G304,G302 -- path validated by the manifest; 0700 only for binaries
	if err != nil {
		return err
	}
	h := sha256.New()
	// Read one byte more than declared to detect oversize members (zip bombs
	// lie about their uncompressed size in the header).
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(rc, f.Size+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n != f.Size || hex.EncodeToString(h.Sum(nil)) != f.SHA256 {
		return fmt.Errorf("%s does not match the manifest", f.Path)
	}
	return nil
}

// VerifyFiles re-hashes the extracted files of m under dir. The agent calls
// it before every run, to detect tampering of its module cache.
func VerifyFiles(m *Manifest, dir string) error {
	for _, f := range m.Files {
		p := filepath.Join(dir, filepath.FromSlash(f.Path))
		fh, err := os.Open(p) // #nosec G304 -- path validated by the manifest
		if err != nil {
			return err
		}
		h := sha256.New()
		n, err := io.Copy(h, io.LimitReader(fh, f.Size+1))
		if cerr := fh.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
		if n != f.Size || hex.EncodeToString(h.Sum(nil)) != f.SHA256 {
			return fmt.Errorf("module file %s was modified", f.Path)
		}
	}
	return nil
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
