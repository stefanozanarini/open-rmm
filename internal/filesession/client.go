package filesession

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sync"
)

// ErrClosed: the session ended.
var ErrClosed = errors.New("the session is closed")

// Client is the console's side of a session. Its methods may be called
// concurrently; every request has its own transfer id.
type Client struct {
	sendMu sync.Mutex
	send   func([]byte) error

	mu      sync.Mutex
	nextID  uint32
	waiters map[uint32]chan frame
	err     error
	done    chan struct{}
}

type frame struct {
	m     *Msg
	chunk []byte
}

// NewClient starts reading the agent's frames with recv; send sends one.
func NewClient(recv func() ([]byte, error), send func([]byte) error) *Client {
	c := &Client{send: send, waiters: map[uint32]chan frame{}, done: make(chan struct{})}
	go c.read(recv)
	return c
}

func (c *Client) read(recv func() ([]byte, error)) {
	for {
		b, err := recv()
		if err != nil {
			c.shut(err)
			return
		}
		m, id, chunk, err := Decode(b)
		if err != nil {
			continue
		}
		if m != nil {
			id = m.ID
		} else {
			chunk = append([]byte(nil), chunk...)
		}
		c.mu.Lock()
		w := c.waiters[id]
		c.mu.Unlock()
		if w != nil {
			// Buffered for a full window: a reader that stopped (gone)
			// must not block the session.
			select {
			case w <- frame{m, chunk}:
			case <-c.done:
				return
			}
		}
	}
}

func (c *Client) shut(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err == nil {
		if errors.Is(err, io.EOF) || err == nil {
			err = ErrClosed
		}
		c.err = err
		close(c.done)
	}
}

// Err returns why the session ended, or nil.
func (c *Client) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// Close ends the session.
func (c *Client) Close() {
	_ = c.out(Msg{Op: OpClose})
	c.shut(ErrClosed)
}

func (c *Client) out(m Msg) error {
	return c.raw(EncodeMsg(m))
}

func (c *Client) raw(b []byte) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if err := c.Err(); err != nil {
		return err
	}
	return c.send(b)
}

// open registers a request id.
func (c *Client) open() (uint32, chan frame) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextID++
	ch := make(chan frame, Window*2+4)
	c.waiters[c.nextID] = ch
	return c.nextID, ch
}

func (c *Client) forget(id uint32) {
	c.mu.Lock()
	delete(c.waiters, id)
	c.mu.Unlock()
}

// next waits for the next frame of a request.
func (c *Client) next(ctx context.Context, ch chan frame) (frame, error) {
	select {
	case f := <-ch:
		if f.m != nil && f.m.Op == OpError {
			return f, errors.New(f.m.Error)
		}
		return f, nil
	case <-c.done:
		return frame{}, c.Err()
	case <-ctx.Done():
		return frame{}, ctx.Err()
	}
}

// call sends a request and returns the first answer.
func (c *Client) call(ctx context.Context, m Msg) (*Msg, error) {
	id, ch := c.open()
	defer c.forget(id)
	m.ID = id
	if err := c.out(m); err != nil {
		return nil, err
	}
	for {
		f, err := c.next(ctx, ch)
		if err != nil {
			return nil, err
		}
		if f.m != nil {
			return f.m, nil
		}
	}
}

// Roots returns the agent's drives (or "/") and its path separator.
func (c *Client) Roots(ctx context.Context) ([]string, string, error) {
	m, err := c.call(ctx, Msg{Op: OpRoots})
	if err != nil {
		return nil, "", err
	}
	return m.Roots, m.Sep, nil
}

// List returns a folder of the agent.
func (c *Client) List(ctx context.Context, path string) (*Msg, error) {
	return c.call(ctx, Msg{Op: OpList, Path: path})
}

// Mkdir creates a folder.
func (c *Client) Mkdir(ctx context.Context, path string) error {
	_, err := c.call(ctx, Msg{Op: OpMkdir, Path: path})
	return err
}

// Get downloads a file into w. started is called with the size before the
// first byte is written (e.g. for Content-Length). It returns the bytes
// written and their SHA-256, checked against the agent's.
func (c *Client) Get(ctx context.Context, path string, w io.Writer, started func(size int64)) (int64, string, error) {
	id, ch := c.open()
	defer c.forget(id)
	if err := c.out(Msg{Op: OpGet, ID: id, Path: path}); err != nil {
		return 0, "", err
	}
	cancel := func() { _ = c.out(Msg{Op: OpCancel, ID: id}) }
	f, err := c.next(ctx, ch)
	if err != nil {
		return 0, "", err
	}
	if f.m == nil || f.m.Op != OpFile {
		return 0, "", errors.New("unexpected answer")
	}
	size := f.m.Size
	if started != nil {
		started(size)
	}
	h := sha256.New()
	var n int64
	for {
		f, err := c.next(ctx, ch)
		if err != nil {
			cancel()
			return n, "", err
		}
		if f.m != nil {
			if f.m.Op != OpEnd {
				cancel()
				return n, "", errors.New("unexpected answer")
			}
			sum := hex.EncodeToString(h.Sum(nil))
			if n != size || sum != f.m.SHA256 {
				return n, "", errors.New("the file arrived incomplete or damaged")
			}
			return n, sum, nil
		}
		if _, err := w.Write(f.chunk); err != nil {
			cancel()
			return n, "", err
		}
		h.Write(f.chunk)
		n += int64(len(f.chunk))
		if err := c.out(Msg{Op: OpAck, ID: id, Credit: 1}); err != nil {
			return n, "", err
		}
	}
}

// Put uploads size bytes from r to path and returns their SHA-256.
func (c *Client) Put(ctx context.Context, path string, size int64, overwrite bool, r io.Reader) (string, error) {
	id, ch := c.open()
	defer c.forget(id)
	if err := c.out(Msg{Op: OpPut, ID: id, Path: path, Size: size, Overwrite: overwrite}); err != nil {
		return "", err
	}
	f, err := c.next(ctx, ch)
	if err != nil {
		return "", err
	}
	if f.m == nil || f.m.Op != OpReady {
		return "", errors.New("unexpected answer")
	}
	h := sha256.New()
	buf := make([]byte, ChunkSize)
	var sent int64
	for sent < size {
		n, rerr := io.ReadFull(r, buf[:min(int64(len(buf)), size-sent)])
		if n > 0 {
			h.Write(buf[:n])
			if err := c.raw(EncodeData(id, buf[:n])); err != nil {
				return "", err
			}
			sent += int64(n)
		}
		if rerr != nil && sent < size {
			_ = c.out(Msg{Op: OpCancel, ID: id})
			return "", rerr
		}
		// The agent refused the data (disk full, limit): stop early.
		select {
		case f := <-ch:
			if f.m != nil && f.m.Op == OpError {
				return "", errors.New(f.m.Error)
			}
		default:
		}
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if err := c.out(Msg{Op: OpPutEnd, ID: id, SHA256: sum}); err != nil {
		return "", err
	}
	if _, err := c.next(ctx, ch); err != nil {
		return "", err
	}
	return sum, nil
}
