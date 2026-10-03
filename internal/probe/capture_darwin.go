//go:build darwin

package probe

import (
	"errors"
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

// capture reads frames from a macOS BPF device. It needs read access to
// /dev/bpf* (the access_bpf group, as installed by Wireshark, or root).
type capture struct {
	fd  int
	buf []byte
}

// bpfAlign is BPF_WORDALIGN on macOS (sizeof(int32)).
const bpfAlign = 4

func openCapture(iface string, snaplen int, promisc bool) (*capture, error) {
	fd := -1
	var lastErr error
	for i := 0; i < 256; i++ {
		f, err := syscall.Open(fmt.Sprintf("/dev/bpf%d", i), syscall.O_RDONLY, 0)
		if err == nil {
			fd = f
			break
		}
		lastErr = err
		if !errors.Is(err, syscall.EBUSY) {
			break
		}
	}
	if fd < 0 {
		return nil, fmt.Errorf("BPF aygıtı açılamadı (access_bpf grubu veya root gerekir): %w", lastErr)
	}
	fail := func(step string, err error) (*capture, error) {
		syscall.Close(fd)
		return nil, fmt.Errorf("%s: %w", step, err)
	}
	// The buffer size must be set before binding to the interface.
	_, _ = syscall.SetBpfBuflen(fd, 1<<20)
	if err := syscall.SetBpfInterface(fd, iface); err != nil {
		return fail("arayüz "+iface, err)
	}
	if dlt, err := syscall.BpfDatalink(fd); err != nil || dlt != syscall.DLT_EN10MB {
		return fail("bağlantı türü", fmt.Errorf("yalnızca Ethernet/Wi-Fi arayüzleri destekleniyor (DLT %d)", dlt))
	}
	// Reads return at least every 200 ms so the caller can expire flows.
	if err := syscall.SetBpfTimeout(fd, &syscall.Timeval{Usec: 200_000}); err != nil {
		return fail("zaman aşımı", err)
	}
	if promisc {
		if err := syscall.SetBpfPromisc(fd, 1); err != nil {
			return fail("promiscuous", err)
		}
	}
	// Accept every packet, truncated to snaplen bytes (headers only).
	if err := syscall.SetBpf(fd, []syscall.BpfInsn{*syscall.BpfStmt(syscall.BPF_RET|syscall.BPF_K, snaplen)}); err != nil {
		return fail("filtre", err)
	}
	n, err := syscall.BpfBuflen(fd)
	if err != nil {
		return fail("tampon", err)
	}
	return &capture{fd: fd, buf: make([]byte, n)}, nil
}

// read delivers the frames of one BPF buffer: the captured bytes, the
// original frame length and the capture time.
func (c *capture) read(fn func(frame []byte, origLen int, ts time.Time)) error {
	n, err := syscall.Read(c.fd, c.buf)
	if err != nil {
		if errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.EAGAIN) {
			return nil
		}
		return err
	}
	b := c.buf[:n]
	for len(b) >= syscall.SizeofBpfHdr {
		h := (*syscall.BpfHdr)(unsafe.Pointer(&b[0]))
		hl, cl := int(h.Hdrlen), int(h.Caplen)
		if hl+cl > len(b) {
			break
		}
		fn(b[hl:hl+cl], int(h.Datalen), time.Unix(int64(h.Tstamp.Sec), int64(h.Tstamp.Usec)*1000))
		adv := (hl + cl + bpfAlign - 1) &^ (bpfAlign - 1)
		if adv >= len(b) {
			break
		}
		b = b[adv:]
	}
	return nil
}

// drops returns the packets the kernel dropped because the buffer was full.
func (c *capture) drops() uint64 {
	st, err := syscall.BpfStats(c.fd)
	if err != nil {
		return 0
	}
	return uint64(st.Drop)
}

func (c *capture) close() error { return syscall.Close(c.fd) }
