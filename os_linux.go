package smart

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"unsafe"
)

const (
	directionNone  = 0
	directionWrite = 1
	directionRead  = 2

	numberBits    = 8
	typeBits      = 8
	sizeBits      = 14
	directionBits = 2

	numberMask    = (1 << numberBits) - 1
	typeMask      = (1 << typeBits) - 1
	sizeMask      = (1 << sizeBits) - 1
	directionMask = (1 << directionBits) - 1

	numberShift    = 0
	typeShift      = numberShift + numberBits
	sizeShift      = typeShift + typeBits
	directionShift = sizeShift + sizeBits
)

// ioc calculates the ioctl command for the specified direction, type, number and size
func ioc(dir, t, nr, size uintptr) uintptr {
	return (dir << directionShift) | (t << typeShift) | (nr << numberShift) | (size << sizeShift)
}

// ior calculates the ioctl command for a read-ioctl of the specified type, number and size
func ior(t, nr, size uintptr) uintptr {
	return ioc(directionRead, t, nr, size)
}

// iow calculates the ioctl command for a write-ioctl of the specified type, number and size
func iow(t, nr, size uintptr) uintptr {
	return ioc(directionWrite, t, nr, size)
}

// iowr calculates the ioctl command for a read/write-ioctl of the specified type, number and size
func iowr(t, nr, size uintptr) uintptr {
	return ioc(directionWrite|directionRead, t, nr, size)
}

// ioctl executes an ioctl command on the specified file descriptor
func ioctl(fd, cmd, ptr uintptr) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, cmd, ptr)
	if errno != 0 {
		return errno
	}
	return nil
}

func scsiSendCdb(file *os.File, cdb []byte, respBuf []byte) error {
	senseBuf := make([]byte, 32)

	/*
		// TODO: make it work with sg_io_v4 data structure
		hdr := sgIoV4{
			guard:          'Q',
			timeout:        _DEFAULT_TIMEOUT,
			requestLen:     uint32(len(cdb)),
			request:        uint64(uintptr(unsafe.Pointer(&cdb[0]))),
			maxResponseLen: uint32(len(senseBuf)),
			response:       uint64(uintptr(unsafe.Pointer(&senseBuf[0]))),
			dinXferLen:     uint32(len(respBuf)),
			dinXferp:       uint64(uintptr(unsafe.Pointer(&respBuf[0]))),
		}
	*/

	hdr := sgIoHdr{
		interfaceId:    'S',
		dxferDirection: _SG_DXFER_FROM_DEV,
		timeout:        _DEFAULT_TIMEOUT,
		cmdLen:         uint8(len(cdb)),
		mxSbLen:        uint8(len(senseBuf)),
		dxferLen:       uint32(len(respBuf)),
		dxferp:         uintptr(unsafe.Pointer(&respBuf[0])),
		cmdp:           uintptr(unsafe.Pointer(&cdb[0])),
		sbp:            uintptr(unsafe.Pointer(&senseBuf[0])),
	}

	if err := ioctl(file.Fd(), _SG_IO, uintptr(unsafe.Pointer(&hdr))); err != nil {
		return err
	}

	if hdr.info&_SG_INFO_OK_MASK != _SG_INFO_OK {
		return sgioError{
			deviceStatus: uint32(hdr.status),
			hostStatus:   uint32(hdr.hostStatus),
			driverStatus: uint32(hdr.driverStatus),
		}
	}
	return nil
}

func nvmeReadLogPage(file *os.File, logID uint8, buf []byte) error {
	bufLen := len(buf)

	if (bufLen < 4) || (bufLen > 0x4000) || (bufLen%4 != 0) {
		return fmt.Errorf("invalid buffer size")
	}

	cmd := nvmePassthruCmd64{
		opcode:  nvmeAdminGetLogPage,
		nsid:    0xffffffff, // controller-level SMART info
		addr:    uint64(uintptr(unsafe.Pointer(&buf[0]))),
		dataLen: uint32(bufLen),
		cdw10:   uint32(logID) | (((uint32(bufLen) / 4) - 1) << 16),
	}

	return ioctl(file.Fd(), nvmeIoctlAdmin64Cmd, uintptr(unsafe.Pointer(&cmd)))
}

func nvmeReadIdentify(file *os.File, nsid, cns uint32, data []byte) error {
	cmd := nvmePassthruCmd64{
		opcode:  nvmeAdminIdentify,
		nsid:    nsid,
		addr:    uint64(uintptr(unsafe.Pointer(&data[0]))),
		dataLen: uint32(len(data)),
		cdw10:   cns,
	}

	return ioctl(file.Fd(), nvmeIoctlAdmin64Cmd, uintptr(unsafe.Pointer(&cmd)))
}
