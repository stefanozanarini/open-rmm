//go:build windows

package screenhelper

import (
	"bytes"
	"context"
	"image/jpeg"
	"io"
	"log"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/screensession"
)

// frameInterval caps the capture rate: fast enough to feel live, slow
// enough not to flood the session's channel with multi-hundred-KB frames.
const frameInterval = 150 * time.Millisecond

// jpegQuality trades detail for bandwidth; the operator is watching a
// desktop, not inspecting a photo.
const jpegQuality = 55

// Run captures the screen and injects input until stdin closes (the
// agent closes it when the session ends) or ctx is done. It never
// returns an error for a session that simply ended normally.
func Run(stdin io.Reader, stdout io.Writer) error {
	setDPIAware()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go captureLoop(ctx, stdout)

	dec := screensession.Decoder{}
	buf := make([]byte, 4096)
	for {
		n, err := stdin.Read(buf)
		if n > 0 {
			frames, derr := dec.Feed(buf[:n])
			if derr != nil {
				return derr
			}
			for _, f := range frames {
				applyInput(f)
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func applyInput(f screensession.Frame) {
	var err error
	switch f.Kind {
	case screensession.Move:
		err = moveMouse(f.X, f.Y)
	case screensession.Button:
		err = mouseButton(f.Button, f.Down)
	case screensession.Wheel:
		err = mouseWheelInput(f.Wheel)
	case screensession.Key:
		err = keyInput(f.Key, f.Down)
	}
	if err != nil {
		log.Printf("screenhelper: input: %v", err)
	}
}

func captureLoop(ctx context.Context, stdout io.Writer) {
	var lastW, lastH int
	ticker := time.NewTicker(frameInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		img, err := captureScreen()
		if err != nil {
			log.Printf("screenhelper: capture: %v", err)
			continue
		}
		b := img.Bounds()
		if b.Dx() != lastW || b.Dy() != lastH {
			lastW, lastH = b.Dx(), b.Dy()
			if _, err := stdout.Write(screensession.EncodeSize(uint32(lastW), uint32(lastH))); err != nil { // #nosec G115 -- screen dimensions
				return
			}
		}
		var jpegBuf bytes.Buffer
		if err := jpeg.Encode(&jpegBuf, img, &jpeg.Options{Quality: jpegQuality}); err != nil {
			log.Printf("screenhelper: encode: %v", err)
			continue
		}
		if _, err := stdout.Write(screensession.EncodeImage(jpegBuf.Bytes())); err != nil {
			return
		}
	}
}
