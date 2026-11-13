//go:build windows

package screenhelper

// Raw GDI/user32 bindings golang.org/x/sys/windows does not wrap: screen
// capture (GetDC/BitBlt/GetDIBits) and input injection (SendInput). The
// struct layouts below are the stable Win32 ABI (unchanged since XP); the
// padding Go inserts for 8-byte-aligned fields on amd64 matches the
// padding the Win32 headers themselves use, which is why INPUT below ends
// up exactly 40 bytes, the real sizeof(INPUT) on x64.

import (
	"fmt"
	"image"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32 = windows.NewLazySystemDLL("user32.dll")
	gdi32  = windows.NewLazySystemDLL("gdi32.dll")

	procGetSystemMetrics              = user32.NewProc("GetSystemMetrics")
	procGetDC                         = user32.NewProc("GetDC")
	procReleaseDC                     = user32.NewProc("ReleaseDC")
	procSendInput                     = user32.NewProc("SendInput")
	procSetProcessDpiAwarenessContext = user32.NewProc("SetProcessDpiAwarenessContext")

	procCreateCompatibleDC     = gdi32.NewProc("CreateCompatibleDC")
	procCreateCompatibleBitmap = gdi32.NewProc("CreateCompatibleBitmap")
	procSelectObject           = gdi32.NewProc("SelectObject")
	procDeleteObject           = gdi32.NewProc("DeleteObject")
	procDeleteDC               = gdi32.NewProc("DeleteDC")
	procBitBlt                 = gdi32.NewProc("BitBlt")
	procGetDIBits              = gdi32.NewProc("GetDIBits")
)

const (
	smXVirtualScreen  = 76
	smYVirtualScreen  = 77
	smCXVirtualScreen = 78
	smCYVirtualScreen = 79

	srcCopy    = 0x00CC0020
	captureBlt = 0x40000000

	dibRGBColors = 0

	// DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, a predefined pseudo
	// handle (negative, sign-extended to a pointer-sized value).
	perMonitorAwareV2 = ^uintptr(3) // -4, i.e. DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
)

type bitmapInfoHeader struct {
	size          uint32
	width, height int32
	planes        uint16
	bitCount      uint16
	compression   uint32
	sizeImage     uint32
	xPelsPerMeter int32
	yPelsPerMeter int32
	clrUsed       uint32
	clrImportant  uint32
}

// setDPIAware makes the process see real pixels, not a scaled virtual
// screen; best effort, as the API needs Windows 10 1703+.
func setDPIAware() {
	_, _, _ = procSetProcessDpiAwarenessContext.Call(perMonitorAwareV2)
}

func getSystemMetrics(index int) int {
	r, _, _ := procGetSystemMetrics.Call(uintptr(index))
	return int(int32(r)) // #nosec G115 -- GetSystemMetrics returns a signed int
}

// virtualScreen returns the bounding rectangle of every monitor combined.
func virtualScreen() (x, y, w, h int) {
	return getSystemMetrics(smXVirtualScreen), getSystemMetrics(smYVirtualScreen),
		getSystemMetrics(smCXVirtualScreen), getSystemMetrics(smCYVirtualScreen)
}

// captureScreen returns one frame of the whole virtual desktop.
func captureScreen() (*image.RGBA, error) {
	x, y, w, h := virtualScreen()
	if w <= 0 || h <= 0 {
		return nil, fmt.Errorf("invalid virtual screen size %dx%d", w, h)
	}
	hdcScreen, _, _ := procGetDC.Call(0)
	if hdcScreen == 0 {
		return nil, fmt.Errorf("GetDC failed")
	}
	defer procReleaseDC.Call(0, hdcScreen)

	hdcMem, _, _ := procCreateCompatibleDC.Call(hdcScreen)
	if hdcMem == 0 {
		return nil, fmt.Errorf("CreateCompatibleDC failed")
	}
	defer procDeleteDC.Call(hdcMem)

	hBitmap, _, _ := procCreateCompatibleBitmap.Call(hdcScreen, uintptr(w), uintptr(h))
	if hBitmap == 0 {
		return nil, fmt.Errorf("CreateCompatibleBitmap failed")
	}
	defer procDeleteObject.Call(hBitmap)

	oldObj, _, _ := procSelectObject.Call(hdcMem, hBitmap)
	defer procSelectObject.Call(hdcMem, oldObj)

	if ok, _, _ := procBitBlt.Call(hdcMem, 0, 0, uintptr(w), uintptr(h), hdcScreen, uintptr(x), uintptr(y), uintptr(srcCopy|captureBlt)); ok == 0 {
		return nil, fmt.Errorf("BitBlt failed")
	}

	bi := bitmapInfoHeader{
		size: uint32(unsafe.Sizeof(bitmapInfoHeader{})), width: int32(w), height: -int32(h), // top-down
		planes: 1, bitCount: 32, compression: 0,
	}
	buf := make([]byte, w*h*4)
	if r, _, _ := procGetDIBits.Call(hdcMem, hBitmap, 0, uintptr(h),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&bi)), dibRGBColors); r == 0 { // #nosec G103 -- Win32 API call
		return nil, fmt.Errorf("GetDIBits failed")
	}

	img := image.NewRGBA(image.Rect(0, 0, w, h))
	// buf is BGRA (GDI's native order); image.RGBA wants RGBA.
	for i := 0; i < len(buf); i += 4 {
		buf[i], buf[i+2] = buf[i+2], buf[i]
		buf[i+3] = 0xff
	}
	copy(img.Pix, buf)
	return img, nil
}

type mouseInput struct {
	dx, dy      int32
	mouseData   uint32
	dwFlags     uint32
	time        uint32
	dwExtraInfo uintptr
}

type keybdInput struct {
	vk          uint16
	scan        uint16
	flags       uint32
	time        uint32
	dwExtraInfo uintptr
}

// input mirrors Win32's INPUT: on amd64 Go pads it to exactly 40 bytes,
// the real sizeof(INPUT), because mouseInput's trailing uintptr forces
// 8-byte alignment just as the C union does.
type input struct {
	typ uint32
	mi  mouseInput
}

const (
	inputMouse    = 0
	inputKeyboard = 1

	mouseMove        = 0x0001
	mouseLeftDown    = 0x0002
	mouseLeftUp      = 0x0004
	mouseRightDown   = 0x0008
	mouseRightUp     = 0x0010
	mouseMiddleDown  = 0x0020
	mouseMiddleUp    = 0x0040
	mouseWheel       = 0x0800
	mouseAbsolute    = 0x8000
	mouseVirtualDesk = 0x4000

	keyUp = 0x0002
)

func sendInput(in *input) error {
	r, _, err := procSendInput.Call(1, uintptr(unsafe.Pointer(in)), unsafe.Sizeof(*in)) // #nosec G103 -- Win32 API call
	if r == 0 {
		return fmt.Errorf("SendInput: %w", err)
	}
	return nil
}

// moveMouse moves the pointer to (x, y) in virtual-desktop pixels.
func moveMouse(x, y int32) error {
	vx, vy, vw, vh := virtualScreen()
	if vw <= 0 || vh <= 0 {
		return fmt.Errorf("invalid virtual screen")
	}
	nx := uint32((int64(x-int32(vx))*65536 + int64(vw)/2) / int64(vw)) // #nosec G115 -- clamped below
	ny := uint32((int64(y-int32(vy))*65536 + int64(vh)/2) / int64(vh)) // #nosec G115 -- clamped below
	in := &input{typ: inputMouse, mi: mouseInput{
		dx: int32(nx), dy: int32(ny), // #nosec G115 -- normalized mouse coordinate, fits int32
		dwFlags: mouseMove | mouseAbsolute | mouseVirtualDesk,
	}}
	return sendInput(in)
}

var buttonFlags = map[byte][2]uint32{
	0: {mouseLeftDown, mouseLeftUp},
	1: {mouseRightDown, mouseRightUp},
	2: {mouseMiddleDown, mouseMiddleUp},
}

func mouseButton(button byte, down bool) error {
	flags, ok := buttonFlags[button]
	if !ok {
		return fmt.Errorf("invalid mouse button %d", button)
	}
	flag := flags[1]
	if down {
		flag = flags[0]
	}
	return sendInput(&input{typ: inputMouse, mi: mouseInput{dwFlags: flag}})
}

func mouseWheelInput(delta int32) error {
	return sendInput(&input{typ: inputMouse, mi: mouseInput{
		mouseData: uint32(delta), dwFlags: mouseWheel, // #nosec G115 -- wheel delta round-trips as int32
	}})
}

func keyInput(vk uint32, down bool) error {
	if vk > 0xffff {
		return fmt.Errorf("invalid virtual-key code %d", vk)
	}
	var in input
	in.typ = inputKeyboard
	ki := (*keybdInput)(unsafe.Pointer(&in.mi)) // #nosec G103 -- overlays the same union storage SendInput reads
	ki.vk = uint16(vk)                          // #nosec G115 -- checked above
	if !down {
		ki.flags = keyUp
	}
	return sendInput(&in)
}
