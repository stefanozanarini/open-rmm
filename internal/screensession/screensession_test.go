package screensession

import (
	"bytes"
	"testing"
)

// feedByte feeds every encoded message one byte at a time, the worst case
// for a stream that can split anywhere, and returns every decoded frame
// in order.
func feedByte(t *testing.T, wire []byte) []Frame {
	t.Helper()
	var dec Decoder
	var out []Frame
	for _, b := range wire {
		frames, err := dec.Feed([]byte{b})
		if err != nil {
			t.Fatalf("Feed: %v", err)
		}
		out = append(out, frames...)
	}
	return out
}

func TestRoundTripByteAtATime(t *testing.T) {
	var wire []byte
	wire = append(wire, EncodeSize(1920, 1080)...)
	wire = append(wire, EncodeImage([]byte{1, 2, 3})...)
	wire = append(wire, EncodeMove(-5, 1200)...)
	wire = append(wire, EncodeButton(ButtonRight, true)...)
	wire = append(wire, EncodeWheel(-120)...)
	wire = append(wire, EncodeKey(0x41, false)...)

	frames := feedByte(t, wire)
	if len(frames) != 6 {
		t.Fatalf("got %d frames, want 6", len(frames))
	}
	if frames[0].Kind != Size || frames[0].Width != 1920 || frames[0].Height != 1080 {
		t.Errorf("size frame: %+v", frames[0])
	}
	if frames[1].Kind != Image || !bytes.Equal(frames[1].Image, []byte{1, 2, 3}) {
		t.Errorf("image frame: %+v", frames[1])
	}
	if frames[2].Kind != Move || frames[2].X != -5 || frames[2].Y != 1200 {
		t.Errorf("move frame: %+v", frames[2])
	}
	if frames[3].Kind != Button || frames[3].Button != ButtonRight || !frames[3].Down {
		t.Errorf("button frame: %+v", frames[3])
	}
	if frames[4].Kind != Wheel || frames[4].Wheel != -120 {
		t.Errorf("wheel frame: %+v", frames[4])
	}
	if frames[5].Kind != Key || frames[5].Key != 0x41 || frames[5].Down {
		t.Errorf("key frame: %+v", frames[5])
	}
}

func TestFeedWholeAndMultipleFramesAtOnce(t *testing.T) {
	var dec Decoder
	wire := append(EncodeButton(ButtonLeft, true), EncodeButton(ButtonLeft, false)...)
	frames, err := dec.Feed(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 2 || !frames[0].Down || frames[1].Down {
		t.Fatalf("frames = %+v", frames)
	}
}

func TestImageTooLarge(t *testing.T) {
	var dec Decoder
	hdr := []byte{Image, 0xff, 0xff, 0xff, 0xff} // declares ~4GB
	if _, err := dec.Feed(hdr); err == nil {
		t.Fatal("expected an error for an oversized frame")
	}
}

func TestUnknownKind(t *testing.T) {
	var dec Decoder
	if _, err := dec.Feed([]byte{'?'}); err == nil {
		t.Fatal("expected an error for an unknown frame kind")
	}
}
