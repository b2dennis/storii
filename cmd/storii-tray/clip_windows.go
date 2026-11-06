package main

import (
	"errors"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Clipboard formats that tell Windows clipboard history, cloud clipboard and clipboard monitors to skip this copy.
var (
	cfExcludeMonitor = call(pRegisterClipboardFormatW, uintptr(unsafe.Pointer(u16("ExcludeClipboardContentFromMonitorProcessing"))))
	cfHistory        = call(pRegisterClipboardFormatW, uintptr(unsafe.Pointer(u16("CanIncludeInClipboardHistory"))))
	cfCloud          = call(pRegisterClipboardFormatW, uintptr(unsafe.Pointer(u16("CanUploadToCloudClipboard"))))
)

// copySecret puts s on the clipboard, kept out of the history, and returns the clipboard sequence number afterwards
// so a later clear only empties it if nothing else was copied in between.
func copySecret(owner uintptr, s string) (uint32, error) {
	var opened bool
	for i := 0; i < 10 && !opened; i++ { // another program may hold it for a moment
		if opened = call(pOpenClipboard, owner) != 0; !opened {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if !opened {
		return 0, errors.New("the clipboard is in use by another program")
	}
	defer call(pCloseClipboard)
	call(pEmptyClipboard)
	text, _ := windows.UTF16FromString(s)
	if err := setClipboard(CF_UNICODETEXT, unsafe.Slice((*byte)(unsafe.Pointer(&text[0])), len(text)*2)); err != nil {
		return 0, err
	}
	zero := []byte{0, 0, 0, 0}
	setClipboard(cfExcludeMonitor, zero)
	setClipboard(cfHistory, zero)
	setClipboard(cfCloud, zero)
	return uint32(call(pGetClipboardSequenceNumber)), nil
}

func setClipboard(format uintptr, data []byte) error {
	h := call(pGlobalAlloc, GMEM_MOVEABLE, uintptr(len(data)))
	if h == 0 {
		return errors.New("out of memory")
	}
	p := call(pGlobalLock, h)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(p)), len(data)), data)
	call(pGlobalUnlock, h)
	if call(pSetClipboardData, format, h) == 0 {
		call(pGlobalFree, h)
		return errors.New("could not set the clipboard")
	}
	return nil // the clipboard owns h now
}

// clearClipboard empties the clipboard if it still holds what we put there (same sequence number).
func clearClipboard(owner uintptr, seq uint32) {
	if seq == 0 || uint32(call(pGetClipboardSequenceNumber)) != seq {
		return
	}
	if call(pOpenClipboard, owner) != 0 {
		call(pEmptyClipboard)
		call(pCloseClipboard)
	}
}
