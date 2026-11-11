package filesession

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Options of the agent's side of a session.
type Options struct {
	// MaxBytes is the largest file transferred (the job's max_bytes).
	MaxBytes int64
	// Deny lists folders that are never read nor written: the agent's
	// configuration, keys, state and program files.
	Deny []string
	// Idle ends a session without requests.
	Idle time.Duration
	// Log records what is read and written (path, size).
	Log func(op, path string, size int64)
}

// Stats sums up a session.
type Stats struct {
	Downloads, Uploads int
	BytesOut, BytesIn  int64
}

// Serve is the agent's side of a session: it answers the console's
// requests until the console closes the session, ctx ends, the stream
// fails or the session is idle. recv returns the data of the next frame,
// send sends one.
func Serve(ctx context.Context, recv func() ([]byte, error), send func([]byte) error, o Options) (Stats, string) {
	s := &server{o: o, send: send, downloads: map[uint32]*download{}, uploads: map[uint32]*upload{}}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type in struct {
		b   []byte
		err error
	}
	frames := make(chan in)
	go func() {
		for {
			b, err := recv()
			select {
			case frames <- in{b, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	idle := time.NewTimer(o.Idle)
	defer idle.Stop()
	defer s.abortAll()
	for {
		select {
		case <-ctx.Done():
			return s.stats(), "timeout"
		case <-idle.C:
			return s.stats(), "idle"
		case f := <-frames:
			if f.err != nil {
				return s.stats(), "disconnected"
			}
			idle.Reset(o.Idle)
			if s.handle(ctx, f.b) {
				return s.stats(), "closed"
			}
		}
	}
}

type server struct {
	o      Options
	sendMu sync.Mutex
	send   func([]byte) error

	mu        sync.Mutex
	downloads map[uint32]*download
	uploads   map[uint32]*upload
	st        Stats
}

type download struct {
	credit chan int
	cancel context.CancelFunc
}

type upload struct {
	f         *os.File
	tmp       string
	path      string
	size      int64
	written   int64
	h         hashWriter
	overwrite bool
}

type hashWriter interface {
	io.Writer
	Sum([]byte) []byte
}

func (s *server) out(m Msg) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	_ = s.send(EncodeMsg(m))
}

func (s *server) fail(id uint32, err error) {
	s.out(Msg{Op: OpError, ID: id, Error: err.Error()})
}

func (s *server) stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st
}

// handle serves one frame; true ends the session.
func (s *server) handle(ctx context.Context, b []byte) bool {
	m, id, chunk, err := Decode(b)
	if err != nil {
		return false
	}
	if m == nil {
		s.write(id, chunk)
		return false
	}
	switch m.Op {
	case OpClose:
		return true
	case OpRoots:
		s.out(Msg{Op: OpRoots, ID: m.ID, Roots: roots(), Sep: string(filepath.Separator)})
	case OpList:
		s.list(m)
	case OpGet:
		s.get(ctx, m)
	case OpAck:
		s.mu.Lock()
		d := s.downloads[m.ID]
		s.mu.Unlock()
		if d != nil && m.Credit > 0 {
			select {
			case d.credit <- m.Credit:
			default:
			}
		}
	case OpCancel:
		s.mu.Lock()
		d, u := s.downloads[m.ID], s.uploads[m.ID]
		delete(s.uploads, m.ID)
		s.mu.Unlock()
		if d != nil {
			d.cancel()
		}
		if u != nil {
			u.abort()
		}
	case OpPut:
		s.put(m)
	case OpPutEnd:
		s.putEnd(m)
	case OpMkdir:
		s.mkdir(m)
	default:
		s.fail(m.ID, fmt.Errorf("unknown operation %q", m.Op))
	}
	return false
}

// clean checks an absolute path and returns it cleaned.
func (s *server) clean(p string) (string, error) {
	if p == "" || strings.ContainsRune(p, 0) || !filepath.IsAbs(p) {
		return "", errors.New("an absolute path is required")
	}
	p = filepath.Clean(p)
	// The real path decides, not a link pointing into a denied folder.
	real := p
	if r, err := filepath.EvalSymlinks(p); err == nil {
		real = r
	} else if r, err := filepath.EvalSymlinks(filepath.Dir(p)); err == nil {
		real = filepath.Join(r, filepath.Base(p))
	}
	for _, d := range s.o.Deny {
		if d != "" && within(real, d) || d != "" && within(p, d) {
			return "", errors.New("access to the agent's own folders is not allowed")
		}
	}
	return p, nil
}

// within tells whether p is dir or inside it (case-insensitive on Windows).
func within(p, dir string) bool {
	dir = filepath.Clean(dir)
	if runtime.GOOS == "windows" {
		p, dir = strings.ToLower(p), strings.ToLower(dir)
	}
	return p == dir || strings.HasPrefix(p, strings.TrimSuffix(dir, string(filepath.Separator))+string(filepath.Separator))
}

func (s *server) list(m *Msg) {
	p, err := s.clean(m.Path)
	if err != nil {
		s.fail(m.ID, err)
		return
	}
	dir, err := os.ReadDir(p)
	if err != nil && len(dir) == 0 {
		s.fail(m.ID, err)
		return
	}
	out := Msg{Op: OpList, ID: m.ID, Path: p, Sep: string(filepath.Separator)}
	for _, d := range dir {
		if len(out.Entries) == MaxEntries {
			out.Truncated = true
			break
		}
		e := Entry{Name: d.Name(), Dir: d.IsDir(), Link: d.Type()&fs.ModeSymlink != 0}
		if info, err := d.Info(); err == nil {
			e.Modified = info.ModTime().UTC()
			if !e.Dir {
				e.Size = info.Size()
			}
		}
		if e.Link {
			if info, err := os.Stat(filepath.Join(p, d.Name())); err == nil {
				e.Dir = info.IsDir()
			}
		}
		out.Entries = append(out.Entries, e)
	}
	sort.Slice(out.Entries, func(i, j int) bool {
		a, b := out.Entries[i], out.Entries[j]
		if a.Dir != b.Dir {
			return a.Dir
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	s.out(out)
}

// get sends a file, paced by the console's credits.
func (s *server) get(ctx context.Context, m *Msg) {
	p, err := s.clean(m.Path)
	if err != nil {
		s.fail(m.ID, err)
		return
	}
	f, err := os.Open(p) // #nosec G304 -- path checked by clean
	if err != nil {
		s.fail(m.ID, err)
		return
	}
	info, err := f.Stat()
	if err == nil && info.IsDir() {
		err = errors.New("it is a folder")
	}
	if err == nil && info.Size() > s.o.MaxBytes {
		err = fmt.Errorf("the file is larger than the limit of %s", Bytes(s.o.MaxBytes))
	}
	if err != nil {
		f.Close()
		s.fail(m.ID, err)
		return
	}
	dctx, cancel := context.WithCancel(ctx)
	d := &download{credit: make(chan int, Window*2), cancel: cancel}
	s.mu.Lock()
	s.downloads[m.ID] = d
	s.st.Downloads++
	s.mu.Unlock()
	if s.o.Log != nil {
		s.o.Log("download", p, info.Size())
	}
	s.out(Msg{Op: OpFile, ID: m.ID, Path: p, Size: info.Size()})
	go func() {
		defer f.Close()
		defer cancel()
		defer func() {
			s.mu.Lock()
			delete(s.downloads, m.ID)
			s.mu.Unlock()
		}()
		h := sha256.New()
		buf := make([]byte, ChunkSize)
		credit := Window
		for {
			for credit == 0 {
				select {
				case c := <-d.credit:
					credit += c
				case <-dctx.Done():
					return
				}
			}
			n, err := f.Read(buf)
			if n > 0 {
				h.Write(buf[:n])
				s.sendMu.Lock()
				serr := s.send(EncodeData(m.ID, buf[:n]))
				s.sendMu.Unlock()
				if serr != nil {
					return
				}
				credit--
				s.mu.Lock()
				s.st.BytesOut += int64(n)
				s.mu.Unlock()
			}
			if errors.Is(err, io.EOF) {
				s.out(Msg{Op: OpEnd, ID: m.ID, SHA256: hex.EncodeToString(h.Sum(nil))})
				return
			}
			if err != nil {
				s.fail(m.ID, err)
				return
			}
		}
	}()
}

// put starts an upload into a temporary file next to the target.
func (s *server) put(m *Msg) {
	p, err := s.clean(m.Path)
	if err == nil && (m.Size < 0 || m.Size > s.o.MaxBytes) {
		err = fmt.Errorf("the file is larger than the limit of %s", Bytes(s.o.MaxBytes))
	}
	if err == nil {
		if info, serr := os.Stat(p); serr == nil {
			if info.IsDir() {
				err = errors.New("a folder with that name exists")
			} else if !m.Overwrite {
				err = errors.New("the file exists")
			}
		}
	}
	if err == nil {
		if info, serr := os.Stat(filepath.Dir(p)); serr != nil || !info.IsDir() {
			err = errors.New("the destination folder does not exist")
		}
	}
	if err != nil {
		s.fail(m.ID, err)
		return
	}
	tmp := filepath.Join(filepath.Dir(p), "."+filepath.Base(p)+".tempra-"+strconv.FormatUint(uint64(m.ID), 10)+".part")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) // #nosec G304 G302 -- next to a checked path; a normal file
	if err != nil {
		s.fail(m.ID, err)
		return
	}
	s.mu.Lock()
	s.uploads[m.ID] = &upload{f: f, tmp: tmp, path: p, size: m.Size, h: sha256.New(), overwrite: m.Overwrite}
	s.mu.Unlock()
	s.out(Msg{Op: OpReady, ID: m.ID})
}

func (u *upload) abort() {
	u.f.Close()
	_ = os.Remove(u.tmp)
}

func (s *server) write(id uint32, chunk []byte) {
	s.mu.Lock()
	u := s.uploads[id]
	s.mu.Unlock()
	if u == nil {
		return
	}
	var err error
	if u.written+int64(len(chunk)) > u.size {
		err = errors.New("more data than announced")
	} else if _, err = u.f.Write(chunk); err == nil {
		u.h.Write(chunk)
		u.written += int64(len(chunk))
		s.mu.Lock()
		s.st.BytesIn += int64(len(chunk))
		s.mu.Unlock()
	}
	if err != nil {
		s.mu.Lock()
		delete(s.uploads, id)
		s.mu.Unlock()
		u.abort()
		s.fail(id, err)
	}
}

// putEnd checks size and digest, then puts the file in place.
func (s *server) putEnd(m *Msg) {
	s.mu.Lock()
	u := s.uploads[m.ID]
	delete(s.uploads, m.ID)
	s.mu.Unlock()
	if u == nil {
		s.fail(m.ID, errors.New("no upload in progress"))
		return
	}
	var err error
	if sum := hex.EncodeToString(u.h.Sum(nil)); u.written != u.size || !strings.EqualFold(sum, m.SHA256) {
		err = errors.New("the file arrived incomplete or damaged")
	}
	if err == nil {
		err = u.f.Sync()
	}
	if cerr := u.f.Close(); err == nil {
		err = cerr
	}
	if err == nil && u.overwrite {
		// Windows does not rename over an existing file.
		if rerr := os.Remove(u.path); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			err = rerr
		}
	}
	if err == nil {
		err = os.Rename(u.tmp, u.path)
	}
	if err != nil {
		_ = os.Remove(u.tmp)
		s.fail(m.ID, err)
		return
	}
	s.mu.Lock()
	s.st.Uploads++
	s.mu.Unlock()
	if s.o.Log != nil {
		s.o.Log("upload", u.path, u.size)
	}
	s.out(Msg{Op: OpOK, ID: m.ID})
}

func (s *server) mkdir(m *Msg) {
	p, err := s.clean(m.Path)
	if err == nil {
		err = os.Mkdir(p, 0o755) // #nosec G301 -- a normal folder
	}
	if err != nil {
		s.fail(m.ID, err)
		return
	}
	if s.o.Log != nil {
		s.o.Log("mkdir", p, 0)
	}
	s.out(Msg{Op: OpOK, ID: m.ID})
}

func (s *server) abortAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, u := range s.uploads {
		u.abort()
		delete(s.uploads, id)
	}
	for _, d := range s.downloads {
		d.cancel()
	}
}

// roots returns the drives (Windows) or "/".
func roots() []string {
	if runtime.GOOS != "windows" {
		return []string{"/"}
	}
	var out []string
	for c := 'A'; c <= 'Z'; c++ {
		d := string(c) + `:\`
		if _, err := os.Stat(d); err == nil {
			out = append(out, d)
		}
	}
	return out
}

// Bytes formats a size for messages.
func Bytes(n int64) string {
	switch {
	case n >= 1<<30:
		return strconv.FormatFloat(float64(n)/(1<<30), 'f', 1, 64) + " GB"
	case n >= 1<<20:
		return strconv.FormatFloat(float64(n)/(1<<20), 'f', 1, 64) + " MB"
	case n >= 1<<10:
		return strconv.FormatFloat(float64(n)/(1<<10), 'f', 1, 64) + " KB"
	}
	return strconv.FormatInt(n, 10) + " B"
}
