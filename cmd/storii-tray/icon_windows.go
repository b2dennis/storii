package main

import (
	"embed"
	"fmt"
	"unsafe"
)

//go:embed icons/*.png
var icons embed.FS

var iconSizes = []int{16, 20, 24, 32, 40, 48, 64, 256}

// loadIcon makes an icon of the given pixel size from the closest embedded PNG at or above it.
func loadIcon(size uintptr) uintptr {
	pick := iconSizes[len(iconSizes)-1]
	for _, s := range iconSizes {
		if uintptr(s) >= size {
			pick = s
			break
		}
	}
	png, err := icons.ReadFile(fmt.Sprintf("icons/icon-%d.png", pick))
	if err != nil {
		return 0
	}
	return call(pCreateIconFromResourceEx, uintptr(unsafe.Pointer(&png[0])), uintptr(len(png)), 1, 0x00030000,
		size, size, 0)
}
