//go:build windows

package screenhelper

// Screen capture through the DXGI Desktop Duplication API, called as raw
// COM vtables: BitBlt from the screen DC returns black frames on many
// Windows 10/11 machines, while duplication reads the composed desktop
// straight from the GPU. Each monitor (DXGI output) is duplicated on its
// own and composed into one image of the whole virtual desktop, so the
// frame keeps the same coordinates BitBlt gave and input mapping is
// unchanged. When duplication cannot be set up at all, capture falls back
// to the GDI path in win32_windows.go.
//
// Vtable indices and IIDs below were checked against the Windows SDK
// interface definitions (dxgi.h, dxgi1_2.h, d3d11.h); every index counts
// the inherited IUnknown/IDXGIObject/ID3D11DeviceChild methods first.

import (
	"errors"
	"fmt"
	"image"
	"log"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	dxgiDLL  = windows.NewLazySystemDLL("dxgi.dll")
	d3d11DLL = windows.NewLazySystemDLL("d3d11.dll")

	procCreateDXGIFactory1 = dxgiDLL.NewProc("CreateDXGIFactory1")
	procD3D11CreateDevice  = d3d11DLL.NewProc("D3D11CreateDevice")

	procOpenInputDesktop          = user32.NewProc("OpenInputDesktop")
	procGetThreadDesktop          = user32.NewProc("GetThreadDesktop")
	procCloseDesktop              = user32.NewProc("CloseDesktop")
	procGetUserObjectInformationW = user32.NewProc("GetUserObjectInformationW")
)

var (
	iidIDXGIFactory1  = windows.GUID{Data1: 0x770aae78, Data2: 0xf26f, Data3: 0x4dba, Data4: [8]byte{0xa8, 0x29, 0x25, 0x3c, 0x83, 0xd1, 0xb3, 0x87}}
	iidIDXGIOutput1   = windows.GUID{Data1: 0x00cddea8, Data2: 0x939b, Data3: 0x4b83, Data4: [8]byte{0xa3, 0x40, 0xa6, 0x85, 0x22, 0x66, 0x66, 0xcc}}
	iidID3D11Texture2 = windows.GUID{Data1: 0x6f15aaf2, Data2: 0xd208, Data3: 0x4e89, Data4: [8]byte{0x9a, 0xb4, 0x48, 0x95, 0x35, 0xd3, 0x4f, 0x9c}}
)

const (
	vtQueryInterface = 0
	vtRelease        = 2

	vtFactory1EnumAdapters1  = 12 // IDXGIFactory1
	vtAdapterEnumOutputs     = 7  // IDXGIAdapter
	vtOutputGetDesc          = 7  // IDXGIOutput
	vtOutput1DuplicateOutput = 22 // IDXGIOutput1
	vtDuplGetDesc            = 7  // IDXGIOutputDuplication
	vtDuplAcquireNextFrame   = 8
	vtDuplReleaseFrame       = 14
	vtDeviceCreateTexture2D  = 5  // ID3D11Device
	vtContextMap             = 14 // ID3D11DeviceContext
	vtContextUnmap           = 15
	vtContextCopyResource    = 47
	vtTexture2DGetDesc       = 10 // ID3D11Texture2D
)

const (
	dxgiErrorNotFound    hresult = 0x887A0002
	dxgiErrorAccessLost  hresult = 0x887A0026
	dxgiErrorWaitTimeout hresult = 0x887A0027
	eAccessDenied        hresult = 0x80070005

	d3dDriverTypeUnknown = 0
	d3d11SDKVersion      = 7
	d3d11UsageStaging    = 3
	d3d11CPUAccessRead   = 0x20000
	d3d11MapRead         = 1

	rotate90  = 2 // DXGI_MODE_ROTATION_ROTATE90
	rotate180 = 3
	rotate270 = 4

	uoiName           = 2      // GetUserObjectInformation: UOI_NAME
	desktopReadObject = 0x0001 // DESKTOP_READOBJECTS
)

// firstFrameTimeout is how long a fresh duplication waits for its first
// frame, which always carries the full desktop image. Later acquires do
// not wait: an unchanged screen just keeps the previous image.
const firstFrameTimeout = 200

// errDesktopInaccessible means the input desktop is not the user's
// (Winlogon while locked, the secure desktop of a UAC prompt), which a
// process running as the user can neither duplicate nor BitBlt.
var errDesktopInaccessible = errors.New("input desktop not accessible (screen locked or UAC prompt?)")

// errLayoutChanged means the monitor layout changed under a duplication.
var errLayoutChanged = errors.New("monitor layout changed")

type hresult uint32

func (h hresult) failed() bool { return int32(h) < 0 } // #nosec G115 -- HRESULT sign bit marks failure

type comError struct {
	op string
	hr hresult
}

func (e *comError) Error() string { return fmt.Sprintf("%s: HRESULT 0x%08X", e.op, uint32(e.hr)) }

func check(op string, hr hresult) error {
	if hr.failed() {
		return &comError{op: op, hr: hr}
	}
	return nil
}

func isHRESULT(err error, hr hresult) bool {
	var ce *comError
	return errors.As(err, &ce) && ce.hr == hr
}

// comObj is a COM interface pointer: its first word points to the vtable.
type comObj struct{ vtbl *[64]uintptr }

// call invokes vtable method idx with the object as its this pointer.
// uintptrescapes keeps any Go memory passed as uintptr alive and in place
// for the duration of the call, as for windows.Proc.Call.
//
//go:uintptrescapes
func (o *comObj) call(idx int, args ...uintptr) hresult {
	r, _, _ := syscall.SyscallN(o.vtbl[idx], append([]uintptr{uintptr(unsafe.Pointer(o))}, args...)...) // #nosec G103 -- COM call
	return hresult(r)                                                                                   // #nosec G115 -- HRESULT is 32 bits
}

func (o *comObj) release() {
	if o != nil {
		o.call(vtRelease)
	}
}

func (o *comObj) queryInterface(iid *windows.GUID) (*comObj, error) {
	var out *comObj
	if err := check("QueryInterface", o.call(vtQueryInterface, uintptr(unsafe.Pointer(iid)), uintptr(unsafe.Pointer(&out)))); err != nil { // #nosec G103 -- COM call
		return nil, err
	}
	return out, nil
}

type rect struct{ left, top, right, bottom int32 }

type outputDesc struct {
	deviceName        [32]uint16
	desktopCoords     rect
	attachedToDesktop int32
	rotation          uint32
	monitor           uintptr
}

type duplDesc struct {
	width, height uint32
	refreshNum    uint32
	refreshDen    uint32
	format        uint32
	scanlineOrder uint32
	scaling       uint32
	rotation      uint32
	imageInSysMem int32
}

type frameInfo struct {
	lastPresentTime     int64
	lastMouseUpdateTime int64
	accumulatedFrames   uint32
	rectsCoalesced      int32
	protectedMaskedOut  int32
	pointerX, pointerY  int32
	pointerVisible      int32
	totalMetadataSize   uint32
	pointerShapeSize    uint32
}

type texture2DDesc struct {
	width, height  uint32
	mipLevels      uint32
	arraySize      uint32
	format         uint32
	sampleCount    uint32
	sampleQuality  uint32
	usage          uint32
	bindFlags      uint32
	cpuAccessFlags uint32
	miscFlags      uint32
}

type mappedSubresource struct {
	data       *byte
	rowPitch   uint32
	depthPitch uint32
}

// duplOutput is one monitor being duplicated.
type duplOutput struct {
	name     string
	rect     image.Rectangle // in virtual-desktop coordinates
	rotation uint32
	device   *comObj // borrowed from dxgiCapture
	context  *comObj // borrowed from dxgiCapture
	dupl     *comObj
	staging  *comObj
	stageW   uint32
	stageH   uint32
	stageFmt uint32
	primed   bool // a full frame has been copied since duplication began
}

// dxgiCapture duplicates every monitor attached to the desktop and
// composes them into img, which keeps the last image of each monitor so
// that one which did not change since the previous frame costs nothing.
type dxgiCapture struct {
	devices  []*comObj // one device and immediate context per adapter
	contexts []*comObj
	outputs  []*duplOutput
	vx, vy   int
	img      *image.RGBA
}

func newDXGICapture() (*dxgiCapture, error) {
	if err := procCreateDXGIFactory1.Find(); err != nil {
		return nil, err
	}
	var factory *comObj
	r, _, _ := procCreateDXGIFactory1.Call(uintptr(unsafe.Pointer(&iidIDXGIFactory1)), uintptr(unsafe.Pointer(&factory))) // #nosec G103 -- Win32 API call
	if err := check("CreateDXGIFactory1", hresult(r)); err != nil {                                                       // #nosec G115 -- HRESULT is 32 bits
		return nil, err
	}
	defer factory.release()

	vx, vy, vw, vh := virtualScreen()
	if vw <= 0 || vh <= 0 {
		return nil, fmt.Errorf("invalid virtual screen size %dx%d", vw, vh)
	}
	c := &dxgiCapture{vx: vx, vy: vy, img: image.NewRGBA(image.Rect(0, 0, vw, vh))}
	ok := false
	defer func() {
		if !ok {
			c.close()
		}
	}()
	var firstErr error
	for i := uint32(0); ; i++ {
		var adapter *comObj
		hr := factory.call(vtFactory1EnumAdapters1, uintptr(i), uintptr(unsafe.Pointer(&adapter))) // #nosec G103 -- COM call
		if hr == dxgiErrorNotFound {
			break
		}
		if err := check("EnumAdapters1", hr); err != nil {
			return nil, err
		}
		err := c.addAdapter(adapter)
		adapter.release()
		if isHRESULT(err, eAccessDenied) {
			return nil, err
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if len(c.outputs) == 0 {
		if firstErr != nil {
			return nil, firstErr
		}
		return nil, errors.New("no monitor attached to the desktop")
	}
	if firstErr != nil {
		log.Printf("screenhelper: some monitors are not captured: %v", firstErr)
	}
	ok = true
	return c, nil
}

// addAdapter duplicates the adapter's attached outputs, creating the
// adapter's D3D11 device only if it has any: duplication requires a
// device on the very adapter that drives the output.
func (c *dxgiCapture) addAdapter(adapter *comObj) error {
	var device, context *comObj
	var firstErr error
	for i := uint32(0); ; i++ {
		var output *comObj
		hr := adapter.call(vtAdapterEnumOutputs, uintptr(i), uintptr(unsafe.Pointer(&output))) // #nosec G103 -- COM call
		if hr == dxgiErrorNotFound {
			break
		}
		if err := check("EnumOutputs", hr); err != nil {
			return err
		}
		var desc outputDesc
		err := check("IDXGIOutput::GetDesc", output.call(vtOutputGetDesc, uintptr(unsafe.Pointer(&desc)))) // #nosec G103 -- COM call
		if err == nil && desc.attachedToDesktop != 0 {
			if device == nil {
				device, context, err = createDevice(adapter)
				if err == nil {
					c.devices = append(c.devices, device)
					c.contexts = append(c.contexts, context)
				}
			}
			if err == nil {
				err = c.addOutput(output, &desc, device, context)
			}
		}
		output.release()
		if isHRESULT(err, eAccessDenied) {
			return err
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func createDevice(adapter *comObj) (device, context *comObj, err error) {
	r, _, _ := procD3D11CreateDevice.Call(
		uintptr(unsafe.Pointer(adapter)), d3dDriverTypeUnknown, 0, 0, 0, 0, d3d11SDKVersion, // #nosec G103 -- Win32 API call
		uintptr(unsafe.Pointer(&device)), 0, uintptr(unsafe.Pointer(&context))) // #nosec G103 -- Win32 API call
	if err := check("D3D11CreateDevice", hresult(r)); err != nil { // #nosec G115 -- HRESULT is 32 bits
		return nil, nil, err
	}
	return device, context, nil
}

func (c *dxgiCapture) addOutput(output *comObj, desc *outputDesc, device, context *comObj) error {
	name := windows.UTF16ToString(desc.deviceName[:])
	output1, err := output.queryInterface(&iidIDXGIOutput1)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	defer output1.release()
	var dupl *comObj
	if err := check("DuplicateOutput", output1.call(vtOutput1DuplicateOutput, uintptr(unsafe.Pointer(device)), uintptr(unsafe.Pointer(&dupl)))); err != nil { // #nosec G103 -- COM call
		return fmt.Errorf("%s: %w", name, err)
	}
	var dd duplDesc
	dupl.call(vtDuplGetDesc, uintptr(unsafe.Pointer(&dd))) // #nosec G103 -- COM call, returns void
	dc := desc.desktopCoords
	c.outputs = append(c.outputs, &duplOutput{
		name:     name,
		rect:     image.Rect(int(dc.left), int(dc.top), int(dc.right), int(dc.bottom)),
		rotation: dd.rotation,
		device:   device,
		context:  context,
		dupl:     dupl,
	})
	return nil
}

func (c *dxgiCapture) close() {
	for _, o := range c.outputs {
		o.staging.release()
		o.dupl.release()
	}
	for _, ctx := range c.contexts {
		ctx.release()
	}
	for _, d := range c.devices {
		d.release()
	}
	c.outputs, c.contexts, c.devices = nil, nil, nil
}

// frame refreshes img with whatever changed on each monitor. The image is
// reused by the next call.
func (c *dxgiCapture) frame() (*image.RGBA, error) {
	vx, vy, vw, vh := virtualScreen()
	if vx != c.vx || vy != c.vy || vw != c.img.Rect.Dx() || vh != c.img.Rect.Dy() {
		return nil, errLayoutChanged
	}
	for _, o := range c.outputs {
		if err := o.grab(c.img, c.vx, c.vy); err != nil {
			return nil, fmt.Errorf("%s: %w", o.name, err)
		}
	}
	return c.img, nil
}

// grab copies the output's latest frame, if there is a new one, into dst.
func (o *duplOutput) grab(dst *image.RGBA, vx, vy int) error {
	timeout := uintptr(0)
	if !o.primed {
		timeout = firstFrameTimeout
	}
	var info frameInfo
	var res *comObj
	hr := o.dupl.call(vtDuplAcquireNextFrame, timeout, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&res))) // #nosec G103 -- COM call
	if hr == dxgiErrorWaitTimeout {
		return nil
	}
	if err := check("AcquireNextFrame", hr); err != nil {
		return err
	}
	defer o.dupl.call(vtDuplReleaseFrame)
	defer res.release()
	if info.lastPresentTime == 0 {
		return nil // only the pointer moved; the desktop image is unchanged
	}
	tex, err := res.queryInterface(&iidID3D11Texture2)
	if err != nil {
		return err
	}
	defer tex.release()
	var td texture2DDesc
	tex.call(vtTexture2DGetDesc, uintptr(unsafe.Pointer(&td))) // #nosec G103 -- COM call, returns void
	if err := o.ensureStaging(&td); err != nil {
		return err
	}
	o.context.call(vtContextCopyResource, uintptr(unsafe.Pointer(o.staging)), uintptr(unsafe.Pointer(tex))) // #nosec G103 -- COM call, returns void
	var m mappedSubresource
	if err := check("Map", o.context.call(vtContextMap, uintptr(unsafe.Pointer(o.staging)), 0, d3d11MapRead, 0, uintptr(unsafe.Pointer(&m)))); err != nil { // #nosec G103 -- COM call
		return err
	}
	defer o.context.call(vtContextUnmap, uintptr(unsafe.Pointer(o.staging)), 0) // #nosec G103 -- COM call
	src := unsafe.Slice(m.data, int(m.rowPitch)*int(td.height))                 // #nosec G103 -- mapped staging texture, rowPitch*height bytes
	o.blit(dst, vx, vy, src, int(m.rowPitch), int(td.width), int(td.height))
	o.primed = true
	return nil
}

// ensureStaging (re)creates the CPU-readable texture the GPU frame is
// copied into, sized and formatted like the frame (BGRA8 for duplication).
func (o *duplOutput) ensureStaging(td *texture2DDesc) error {
	if o.staging != nil && o.stageW == td.width && o.stageH == td.height && o.stageFmt == td.format {
		return nil
	}
	o.staging.release()
	o.staging = nil
	desc := texture2DDesc{
		width: td.width, height: td.height, mipLevels: 1, arraySize: 1, format: td.format,
		sampleCount: 1, usage: d3d11UsageStaging, cpuAccessFlags: d3d11CPUAccessRead,
	}
	var staging *comObj
	if err := check("CreateTexture2D", o.device.call(vtDeviceCreateTexture2D, uintptr(unsafe.Pointer(&desc)), 0, uintptr(unsafe.Pointer(&staging)))); err != nil { // #nosec G103 -- COM call
		return err
	}
	o.staging, o.stageW, o.stageH, o.stageFmt = staging, td.width, td.height, td.format
	return nil
}

// blit converts the BGRA frame src (tw x th, pitch bytes per row) to RGBA
// at the output's place in dst. The frame is in the panel's native
// orientation, so a rotated monitor is turned back the way Microsoft's
// DXGIDesktopDuplication sample maps its dirty rects.
func (o *duplOutput) blit(dst *image.RGBA, vx, vy int, src []byte, pitch, tw, th int) {
	r := o.rect.Sub(image.Pt(vx, vy))
	vis := r.Intersect(dst.Rect)
	w, h := r.Dx(), r.Dy()
	for y := vis.Min.Y; y < vis.Max.Y; y++ {
		dy := y - r.Min.Y
		d := dst.PixOffset(vis.Min.X, y)
		for x := vis.Min.X; x < vis.Max.X; x, d = x+1, d+4 {
			dx := x - r.Min.X
			sx, sy := dx, dy
			switch o.rotation {
			case rotate90:
				sx, sy = dy, w-1-dx
			case rotate180:
				sx, sy = w-1-dx, h-1-dy
			case rotate270:
				sx, sy = h-1-dy, dx
			}
			if sx >= tw || sy >= th {
				continue
			}
			s := sy*pitch + sx*4
			dst.Pix[d], dst.Pix[d+1], dst.Pix[d+2], dst.Pix[d+3] = src[s+2], src[s+1], src[s], 0xff
		}
	}
}

// Capture runs on one locked OS thread: the duplication belongs to the
// thread's desktop, and its COM objects are not shared between threads.
var (
	captureOnce sync.Once
	captureReqs chan chan captureResult
)

type captureResult struct {
	img *image.RGBA
	err error
}

// captureScreen returns one frame of the whole virtual desktop. The image
// may be reused by the next call, so the caller must be done with it by
// then.
func captureScreen() (*image.RGBA, error) {
	captureOnce.Do(func() {
		captureReqs = make(chan chan captureResult)
		go captureThread(captureReqs)
	})
	reply := make(chan captureResult, 1)
	captureReqs <- reply
	r := <-reply
	return r.img, r.err
}

func captureThread(reqs <-chan chan captureResult) {
	runtime.LockOSThread() // never unlocked: the thread lives as long as the helper
	var sid uint32
	_ = windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sid)
	log.Printf("screenhelper: session %d, thread desktop %s, input desktop %s", sid, threadDesktopName(), inputDesktopName())
	var s captureState
	for reply := range reqs {
		img, err := s.capture()
		reply <- captureResult{img, err}
	}
}

// captureState picks the backend: duplication when it can be set up, GDI
// when it cannot (retried now and then), nothing while the desktop is not
// the user's.
type captureState struct {
	dxgi        *dxgiCapture
	retryAt     time.Time // no duplication attempt before this
	lastDXGIErr string
	backend     string // backend of the last good frame, to log changes
}

func (s *captureState) capture() (*image.RGBA, error) {
	now := time.Now()
	if s.dxgi == nil && !now.Before(s.retryAt) {
		d, err := newDXGICapture()
		switch {
		case err == nil:
			s.dxgi, s.lastDXGIErr = d, ""
			for _, o := range d.outputs {
				log.Printf("screenhelper: duplicating %s at %v, rotation %d", o.name, o.rect, o.rotation)
			}
		case isHRESULT(err, eAccessDenied):
			s.retryAt = now.Add(time.Second)
			return nil, errDesktopInaccessible
		default:
			s.retryAt = now.Add(30 * time.Second)
			if msg := err.Error(); msg != s.lastDXGIErr {
				s.lastDXGIErr = msg
				log.Printf("screenhelper: desktop duplication unavailable, using GDI: %v", err)
			}
		}
	}
	if s.dxgi != nil {
		img, err := s.dxgi.frame()
		if err == nil {
			s.noteBackend("dxgi", img)
			return img, nil
		}
		s.dxgi.close()
		s.dxgi = nil
		switch {
		case isHRESULT(err, dxgiErrorAccessLost), errors.Is(err, errLayoutChanged):
			// Mode change, desktop switch, monitor plugged in or out:
			// duplicate again on the next frame.
			s.retryAt = time.Time{}
		case isHRESULT(err, eAccessDenied):
			s.retryAt = now.Add(time.Second)
			return nil, errDesktopInaccessible
		default:
			s.retryAt = now.Add(time.Second)
		}
		return nil, err
	}
	img, err := captureScreenGDI()
	if err == nil {
		s.noteBackend("gdi", img)
	}
	return img, err
}

// noteBackend logs when the backend changes, with whether its first frame
// is entirely black: the symptom that sent capture to DXGI in the first
// place, worth seeing in the agent log at a glance.
func (s *captureState) noteBackend(name string, img *image.RGBA) {
	if s.backend == name {
		return
	}
	s.backend = name
	black := true
	for i := 0; i < len(img.Pix); i += 4 {
		if img.Pix[i] != 0 || img.Pix[i+1] != 0 || img.Pix[i+2] != 0 {
			black = false
			break
		}
	}
	log.Printf("screenhelper: capturing with %s, %dx%d, first frame black: %v", name, img.Rect.Dx(), img.Rect.Dy(), black)
}

func desktopName(h uintptr) string {
	var buf [256]uint16
	var needed uint32
	r, _, err := procGetUserObjectInformationW.Call(h, uoiName, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)*2), uintptr(unsafe.Pointer(&needed))) // #nosec G103 -- Win32 API call
	if r == 0 {
		return fmt.Sprintf("? (%v)", err)
	}
	return fmt.Sprintf("%q", windows.UTF16ToString(buf[:]))
}

func threadDesktopName() string {
	h, _, err := procGetThreadDesktop.Call(uintptr(windows.GetCurrentThreadId()))
	if h == 0 {
		return fmt.Sprintf("? (%v)", err)
	}
	return desktopName(h) // a thread desktop handle must not be closed
}

func inputDesktopName() string {
	h, _, err := procOpenInputDesktop.Call(0, 0, desktopReadObject)
	if h == 0 {
		return fmt.Sprintf("not accessible (%v)", err)
	}
	defer procCloseDesktop.Call(h)
	return desktopName(h)
}
