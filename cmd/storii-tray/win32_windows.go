package main

// The Win32 calls the tray app uses. golang.org/x/sys/windows loads the DLLs from System32 only.

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	dwmapi   = windows.NewLazySystemDLL("dwmapi.dll")
	wtsapi32 = windows.NewLazySystemDLL("wtsapi32.dll")

	pRegisterClassExW              = user32.NewProc("RegisterClassExW")
	pCreateWindowExW               = user32.NewProc("CreateWindowExW")
	pDefWindowProcW                = user32.NewProc("DefWindowProcW")
	pCallWindowProcW               = user32.NewProc("CallWindowProcW")
	pGetMessageW                   = user32.NewProc("GetMessageW")
	pTranslateMessage              = user32.NewProc("TranslateMessage")
	pDispatchMessageW              = user32.NewProc("DispatchMessageW")
	pPostMessageW                  = user32.NewProc("PostMessageW")
	pSendMessageW                  = user32.NewProc("SendMessageW")
	pPostQuitMessage               = user32.NewProc("PostQuitMessage")
	pShowWindow                    = user32.NewProc("ShowWindow")
	pIsWindowVisible               = user32.NewProc("IsWindowVisible")
	pSetForegroundWindow           = user32.NewProc("SetForegroundWindow")
	pGetForegroundWindow           = user32.NewProc("GetForegroundWindow")
	pSetWindowPos                  = user32.NewProc("SetWindowPos")
	pSetWindowTextW                = user32.NewProc("SetWindowTextW")
	pGetWindowTextW                = user32.NewProc("GetWindowTextW")
	pGetWindowTextLengthW          = user32.NewProc("GetWindowTextLengthW")
	pSetFocus                      = user32.NewProc("SetFocus")
	pGetFocus                      = user32.NewProc("GetFocus")
	pEnableWindow                  = user32.NewProc("EnableWindow")
	pSetWindowLongPtrW             = user32.NewProc("SetWindowLongPtrW")
	pRegisterHotKey                = user32.NewProc("RegisterHotKey")
	pSetTimer                      = user32.NewProc("SetTimer")
	pKillTimer                     = user32.NewProc("KillTimer")
	pLoadCursorW                   = user32.NewProc("LoadCursorW")
	pCreatePopupMenu               = user32.NewProc("CreatePopupMenu")
	pAppendMenuW                   = user32.NewProc("AppendMenuW")
	pTrackPopupMenu                = user32.NewProc("TrackPopupMenu")
	pDestroyMenu                   = user32.NewProc("DestroyMenu")
	pGetCursorPos                  = user32.NewProc("GetCursorPos")
	pMonitorFromPoint              = user32.NewProc("MonitorFromPoint")
	pGetMonitorInfoW               = user32.NewProc("GetMonitorInfoW")
	pGetDpiForWindow               = user32.NewProc("GetDpiForWindow")
	pGetSystemMetricsForDpi        = user32.NewProc("GetSystemMetricsForDpi")
	pSetProcessDpiAwarenessContext = user32.NewProc("SetProcessDpiAwarenessContext")
	pOpenClipboard                 = user32.NewProc("OpenClipboard")
	pCloseClipboard                = user32.NewProc("CloseClipboard")
	pEmptyClipboard                = user32.NewProc("EmptyClipboard")
	pSetClipboardData              = user32.NewProc("SetClipboardData")
	pGetClipboardSequenceNumber    = user32.NewProc("GetClipboardSequenceNumber")
	pRegisterClipboardFormatW      = user32.NewProc("RegisterClipboardFormatW")
	pRegisterWindowMessageW        = user32.NewProc("RegisterWindowMessageW")
	pFindWindowW                   = user32.NewProc("FindWindowW")
	pGetKeyState                   = user32.NewProc("GetKeyState")
	pFillRect                      = user32.NewProc("FillRect")
	pDrawTextW                     = user32.NewProc("DrawTextW")
	pInvalidateRect                = user32.NewProc("InvalidateRect")
	pBeginPaint                    = user32.NewProc("BeginPaint")
	pEndPaint                      = user32.NewProc("EndPaint")
	pGetClientRect                 = user32.NewProc("GetClientRect")
	pCreateIconFromResourceEx      = user32.NewProc("CreateIconFromResourceEx")
	pDestroyIcon                   = user32.NewProc("DestroyIcon")
	pMessageBoxW                   = user32.NewProc("MessageBoxW")
	pAllowSetForegroundWindow      = user32.NewProc("AllowSetForegroundWindow")
	pIsWindow                      = user32.NewProc("IsWindow")
	pDestroyWindow                 = user32.NewProc("DestroyWindow")
	pGetDpiForSystem               = user32.NewProc("GetDpiForSystem")

	pCreateFontW      = gdi32.NewProc("CreateFontW")
	pDeleteObject     = gdi32.NewProc("DeleteObject")
	pSelectObject     = gdi32.NewProc("SelectObject")
	pSetTextColor     = gdi32.NewProc("SetTextColor")
	pSetBkColor       = gdi32.NewProc("SetBkColor")
	pSetBkMode        = gdi32.NewProc("SetBkMode")
	pCreateSolidBrush = gdi32.NewProc("CreateSolidBrush")
	pRoundRect        = gdi32.NewProc("RoundRect")
	pCreatePen        = gdi32.NewProc("CreatePen")

	pGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
	pGlobalAlloc      = kernel32.NewProc("GlobalAlloc")
	pGlobalLock       = kernel32.NewProc("GlobalLock")
	pGlobalUnlock     = kernel32.NewProc("GlobalUnlock")
	pGlobalFree       = kernel32.NewProc("GlobalFree")
	pCreateMutexW     = kernel32.NewProc("CreateMutexW")

	pShellNotifyIconW = shell32.NewProc("Shell_NotifyIconW")
	pShellExecuteW    = shell32.NewProc("ShellExecuteW")

	pDwmSetWindowAttribute = dwmapi.NewProc("DwmSetWindowAttribute")

	pWTSRegisterSessionNotification = wtsapi32.NewProc("WTSRegisterSessionNotification")
)

const (
	WM_DESTROY           = 0x0002
	WM_SIZE              = 0x0005
	WM_ACTIVATE          = 0x0006
	WM_SETFOCUS          = 0x0007
	WM_PAINT             = 0x000F
	WM_CLOSE             = 0x0010
	WM_ERASEBKGND        = 0x0014
	WM_SETTINGCHANGE     = 0x001A
	WM_MEASUREITEM       = 0x002C
	WM_DRAWITEM          = 0x002B
	WM_SETFONT           = 0x0030
	WM_KEYDOWN           = 0x0100
	WM_CHAR              = 0x0102
	WM_SYSKEYDOWN        = 0x0104
	WM_COMMAND           = 0x0111
	WM_TIMER             = 0x0113
	WM_CTLCOLOREDIT      = 0x0133
	WM_CTLCOLORLISTBOX   = 0x0134
	WM_CTLCOLORSTATIC    = 0x0138
	WM_LBUTTONUP         = 0x0202
	WM_RBUTTONUP         = 0x0205
	WM_CONTEXTMENU       = 0x007B
	WM_POWERBROADCAST    = 0x0218
	WM_WTSSESSION_CHANGE = 0x02B1
	WM_HOTKEY            = 0x0312
	WM_DPICHANGED        = 0x02E0
	WM_APP               = 0x8000

	NIN_SELECT    = 0x0400
	NIN_KEYSELECT = 0x0401

	WS_POPUP         = 0x80000000
	WS_CHILD         = 0x40000000
	WS_CLIPCHILDREN  = 0x02000000
	WS_VISIBLE       = 0x10000000
	WS_VSCROLL       = 0x00200000
	WS_TABSTOP       = 0x00010000
	WS_EX_TOPMOST    = 0x00000008
	WS_EX_TOOLWINDOW = 0x00000080

	ES_AUTOHSCROLL = 0x0080
	ES_PASSWORD    = 0x0020
	ES_READONLY    = 0x0800

	LBS_NOTIFY           = 0x0001
	LBS_OWNERDRAWFIXED   = 0x0010
	LBS_NOINTEGRALHEIGHT = 0x0100
	LBS_NODATA           = 0x2000
	LB_SETCURSEL         = 0x0186
	LB_GETCURSEL         = 0x0188
	LB_SETCOUNT          = 0x01A7
	LB_RESETCONTENT      = 0x0184
	LB_SETITEMHEIGHT     = 0x01A0
	LB_GETTOPINDEX       = 0x018E
	LBN_SELCHANGE        = 1
	LBN_DBLCLK           = 2

	EM_SETSEL       = 0x00B1
	EM_SETCUEBANNER = 0x1501
	EM_SETMARGINS   = 0x00D3
	EM_REPLACESEL   = 0x00C2
	EM_GETSEL       = 0x00B0
	EC_LEFTMARGIN   = 1
	EC_RIGHTMARGIN  = 2
	EN_CHANGE       = 0x0300

	SW_HIDE = 0
	SW_SHOW = 5

	SWP_NOZORDER   = 0x0004
	SWP_NOACTIVATE = 0x0010
	SWP_SHOWWINDOW = 0x0040

	CS_DROPSHADOW = 0x00020000

	MF_STRING       = 0x0000
	MF_SEPARATOR    = 0x0800
	MF_CHECKED      = 0x0008
	MF_GRAYED       = 0x0001
	TPM_RIGHTBUTTON = 0x0002
	TPM_RETURNCMD   = 0x0100
	TPM_BOTTOMALIGN = 0x0020

	MOD_ALT      = 0x0001
	MOD_CONTROL  = 0x0002
	MOD_SHIFT    = 0x0004
	MOD_WIN      = 0x0008
	MOD_NOREPEAT = 0x4000

	VK_BACK    = 0x08
	VK_TAB     = 0x09
	VK_RETURN  = 0x0D
	VK_SHIFT   = 0x10
	VK_CONTROL = 0x11
	VK_MENU    = 0x12
	VK_ESCAPE  = 0x1B
	VK_SPACE   = 0x20
	VK_PRIOR   = 0x21
	VK_NEXT    = 0x22
	VK_END     = 0x23
	VK_HOME    = 0x24
	VK_UP      = 0x26
	VK_DOWN    = 0x28
	VK_INSERT  = 0x2D
	VK_F1      = 0x70

	NIM_ADD              = 0
	NIM_MODIFY           = 1
	NIM_DELETE           = 2
	NIM_SETVERSION       = 4
	NIF_MESSAGE          = 0x01
	NIF_ICON             = 0x02
	NIF_TIP              = 0x04
	NIF_INFO             = 0x10
	NIF_SHOWTIP          = 0x80
	NIIF_WARNING         = 0x02
	NOTIFYICON_VERSION_4 = 4

	CF_UNICODETEXT = 13
	GMEM_MOVEABLE  = 0x0002

	ODS_SELECTED    = 0x0001
	DT_LEFT         = 0x0000
	DT_RIGHT        = 0x0002
	DT_VCENTER      = 0x0004
	DT_SINGLELINE   = 0x0020
	DT_NOPREFIX     = 0x0800
	DT_END_ELLIPSIS = 0x8000
	TRANSPARENT     = 1

	DWMWA_USE_IMMERSIVE_DARK_MODE  = 20
	DWMWA_WINDOW_CORNER_PREFERENCE = 33
	DWMWA_BORDER_COLOR             = 34
	DWMWCP_ROUND                   = 2

	WA_INACTIVE             = 0
	WTS_SESSION_LOCK        = 0x7
	PBT_APMSUSPEND          = 0x4
	NOTIFY_FOR_THIS_SESSION = 0

	SM_CXSMICON  = 49
	MB_ICONERROR = 0x10
	IDC_ARROW    = 32512
	FW_NORMAL    = 400
	FW_SEMIBOLD  = 600

	ERROR_ALREADY_EXISTS = 183
)

type POINT struct{ X, Y int32 }
type RECT struct{ Left, Top, Right, Bottom int32 }

type MSG struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      POINT
	private uint32
}

type WNDCLASSEXW struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   uintptr
	Icon       uintptr
	Cursor     uintptr
	Background uintptr
	MenuName   *uint16
	ClassName  *uint16
	IconSm     uintptr
}

type NOTIFYICONDATAW struct {
	Size            uint32
	Wnd             uintptr
	ID              uint32
	Flags           uint32
	CallbackMessage uint32
	Icon            uintptr
	Tip             [128]uint16
	State           uint32
	StateMask       uint32
	Info            [256]uint16
	Version         uint32
	InfoTitle       [64]uint16
	InfoFlags       uint32
	GuidItem        windows.GUID
	BalloonIcon     uintptr
}

type MONITORINFO struct {
	Size    uint32
	Monitor RECT
	Work    RECT
	Flags   uint32
}

type PAINTSTRUCT struct {
	Hdc       uintptr
	Erase     int32
	Paint     RECT
	Restore   int32
	IncUpdate int32
	Reserved  [32]byte
}

type DRAWITEMSTRUCT struct {
	CtlType    uint32
	CtlID      uint32
	ItemID     uint32
	ItemAction uint32
	ItemState  uint32
	HwndItem   uintptr
	Hdc        uintptr
	Rc         RECT
	ItemData   uintptr
}

type MEASUREITEMSTRUCT struct {
	CtlType    uint32
	CtlID      uint32
	ItemID     uint32
	ItemWidth  uint32
	ItemHeight uint32
	ItemData   uintptr
}

func u16(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

func call(p *windows.LazyProc, args ...uintptr) uintptr {
	r, _, _ := p.Call(args...)
	return r
}

func send(h uintptr, msg uint32, w, l uintptr) uintptr {
	return call(pSendMessageW, h, uintptr(msg), w, l)
}
func post(h uintptr, msg uint32, w, l uintptr) { call(pPostMessageW, h, uintptr(msg), w, l) }

func windowText(h uintptr) string {
	n := call(pGetWindowTextLengthW, h)
	buf := make([]uint16, n+1)
	call(pGetWindowTextW, h, uintptr(unsafe.Pointer(&buf[0])), n+1)
	return windows.UTF16ToString(buf)
}

func setText(h uintptr, s string) { call(pSetWindowTextW, h, uintptr(unsafe.Pointer(u16(s)))) }

func keyDown(vk int) bool { return int16(call(pGetKeyState, uintptr(vk))) < 0 }

func rgb(c uint32) uintptr { return uintptr((c>>16)&0xff | (c & 0xff00) | (c&0xff)<<16) } // 0xRRGGBB → COLORREF

func loword(x uintptr) uint32 { return uint32(x & 0xffff) }
func hiword(x uintptr) uint32 { return uint32((x >> 16) & 0xffff) }

func messageBox(text string) {
	call(pMessageBoxW, 0, uintptr(unsafe.Pointer(u16(text))), uintptr(unsafe.Pointer(u16("storii"))), MB_ICONERROR)
}

func systemDPI() uint32 { return uint32(call(pGetDpiForSystem)) }
