// Package screensession is the wire protocol of the interactive
// remote-control sessions: an operator watches an agent's screen and
// moves its mouse/keyboard.
//
// A session is a signed job of a module with the screen_session
// capability; its frames travel over the same stream as the interactive
// shell (ShellFrame.data), so the gateway and the relay carry them
// unchanged, exactly as they already do for file sessions. Neither of
// them parses this protocol: only the two real endpoints do — the
// screenhelper process in the user's session, and the console web
// handler. The byte stream may be split at arbitrary points by the
// pipes/gRPC/WebSocket it crosses, so every frame is explicitly
// delimited; nothing here assumes a write on one side arrives whole on
// the other.
//
// From the helper to the console:
//
//	'S' + 4-byte width + 4-byte height (big-endian): the virtual desktop
//	    size, sent once at the start and again if it changes.
//	'F' + 4-byte length + JPEG bytes: one screen frame.
//
// From the console to the helper:
//
//	'M' + 4-byte x + 4-byte y (big-endian, signed, virtual-desktop pixels):
//	    move the mouse.
//	'B' + 1 button byte (0 left, 1 right, 2 middle) + 1 down byte (0/1):
//	    a mouse button.
//	'W' + 4-byte delta (big-endian, signed): the vertical wheel.
//	'K' + 4-byte virtual-key code (big-endian) + 1 down byte (0/1): a key.
//
// The session's end is carried by ShellFrame.close itself, like the
// shell: no close marker is needed in this protocol.
package screensession

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Frame kinds.
const (
	Size   = 'S'
	Image  = 'F'
	Move   = 'M'
	Button = 'B'
	Wheel  = 'W'
	Key    = 'K'
)

// Mouse buttons.
const (
	ButtonLeft = iota
	ButtonRight
	ButtonMiddle
)

// MaxImageSize bounds a single decoded image frame.
const MaxImageSize = 8 << 20

// Frame is one decoded message.
type Frame struct {
	Kind          byte
	X, Y          int32  // Move
	Width, Height uint32 // Size
	Button        byte   // Button
	Down          bool   // Button, Key
	Wheel         int32  // Wheel
	Key           uint32 // Key
	Image         []byte // Image (shares the decoder's buffer: copy before reuse)
}

// EncodeSize returns the wire bytes of a Size frame.
func EncodeSize(width, height uint32) []byte {
	b := make([]byte, 9)
	b[0] = Size
	binary.BigEndian.PutUint32(b[1:], width)
	binary.BigEndian.PutUint32(b[5:], height)
	return b
}

// EncodeImage returns the wire bytes of an Image frame.
func EncodeImage(jpeg []byte) []byte {
	b := make([]byte, 5+len(jpeg))
	b[0] = Image
	binary.BigEndian.PutUint32(b[1:], uint32(len(jpeg))) // #nosec G115 -- bounded by the encoder
	copy(b[5:], jpeg)
	return b
}

// EncodeMove returns the wire bytes of a Move frame.
func EncodeMove(x, y int32) []byte {
	b := make([]byte, 9)
	b[0] = Move
	binary.BigEndian.PutUint32(b[1:], uint32(x)) // #nosec G115 -- round-trips through DecodeMove
	binary.BigEndian.PutUint32(b[5:], uint32(y)) // #nosec G115 -- round-trips through DecodeMove
	return b
}

// EncodeButton returns the wire bytes of a Button frame.
func EncodeButton(button byte, down bool) []byte {
	return []byte{Button, button, boolByte(down)}
}

// EncodeWheel returns the wire bytes of a Wheel frame.
func EncodeWheel(delta int32) []byte {
	b := make([]byte, 5)
	b[0] = Wheel
	binary.BigEndian.PutUint32(b[1:], uint32(delta)) // #nosec G115 -- round-trips through DecodeWheel
	return b
}

// EncodeKey returns the wire bytes of a Key frame.
func EncodeKey(vk uint32, down bool) []byte {
	b := make([]byte, 6)
	b[0] = Key
	binary.BigEndian.PutUint32(b[1:], vk)
	b[5] = boolByte(down)
	return b
}

func boolByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

// fixedLen is the payload length (after the tag byte) of every frame kind
// except Image, whose length is carried in its own 4-byte prefix.
var fixedLen = map[byte]int{Size: 8, Move: 8, Button: 2, Wheel: 4, Key: 5}

// Decoder reassembles frames out of a byte stream that may be split at
// arbitrary points. It is not safe for concurrent use.
type Decoder struct {
	buf []byte
}

// ErrFrameTooLarge is returned when an Image frame's declared length
// exceeds MaxImageSize: the stream is no longer trustworthy and must be
// closed, not resynchronized.
var ErrFrameTooLarge = errors.New("screensession: frame too large")

// Feed appends data and returns every frame now complete. The returned
// frames' Image slices alias Feed's internal buffer and must be copied
// before the next call if kept.
func (d *Decoder) Feed(data []byte) ([]Frame, error) {
	d.buf = append(d.buf, data...)
	var out []Frame
	for {
		if len(d.buf) == 0 {
			return out, nil
		}
		kind := d.buf[0]
		if kind == Image {
			if len(d.buf) < 5 {
				return out, nil
			}
			n := binary.BigEndian.Uint32(d.buf[1:5])
			if n > MaxImageSize {
				return out, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, n)
			}
			total := 5 + int(n)
			if len(d.buf) < total {
				return out, nil
			}
			out = append(out, Frame{Kind: Image, Image: d.buf[5:total]})
			d.buf = d.buf[total:]
			continue
		}
		n, ok := fixedLen[kind]
		if !ok {
			return out, fmt.Errorf("screensession: unknown frame kind %q", kind)
		}
		if len(d.buf) < 1+n {
			return out, nil
		}
		p := d.buf[1 : 1+n]
		f := Frame{Kind: kind}
		switch kind {
		case Size:
			f.Width, f.Height = binary.BigEndian.Uint32(p), binary.BigEndian.Uint32(p[4:])
		case Move:
			f.X, f.Y = int32(binary.BigEndian.Uint32(p)), int32(binary.BigEndian.Uint32(p[4:])) // #nosec G115 -- inverse of EncodeMove
		case Button:
			f.Button, f.Down = p[0], p[1] != 0
		case Wheel:
			f.Wheel = int32(binary.BigEndian.Uint32(p)) // #nosec G115 -- inverse of EncodeWheel
		case Key:
			f.Key, f.Down = binary.BigEndian.Uint32(p), p[4] != 0
		}
		out = append(out, f)
		d.buf = d.buf[1+n:]
	}
}
