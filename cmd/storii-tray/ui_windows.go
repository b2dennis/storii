package main

import (
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/b2dennis/storii/internal/quick"
	"github.com/b2dennis/storii/internal/vault"
)

// Sizes in device-independent pixels, scaled by the monitor's DPI.
const (
	popupWidth = 580
	pad        = 14
	fieldH     = 38
	gap        = 8
	labelH     = 20
	rowH       = 50
	maxRows    = 7
	footerH    = 32
	headerH    = 46
)

const (
	idSearch = 100 + iota
	idServer
	idUser
	idPass
	idList
)

type theme struct{ bg, field, text, muted, line, accent, accentText, danger uint32 }

var (
	lightTheme = theme{0xffffff, 0xf6f6f9, 0x1d1d1f, 0x6b6b76, 0xe1e1e8, 0x5856d6, 0xffffff, 0xc4314b}
	darkTheme  = theme{0x232328, 0x1c1c20, 0xf2f2f5, 0xa0a0ab, 0x34343c, 0x7d7aff, 0x0f0f12, 0xff6b81}
)

type ui struct {
	hwnd                                uintptr
	eSearch, eServer, eUser, ePass, lst uintptr
	edits                               []uintptr
	oldEditProc                         uintptr

	m         mode
	query     string
	results   []quick.Result
	status    string
	statusErr bool

	dpi                           uint32
	fBig, fUI, fBold, fSmall      uintptr
	t                             theme
	dark                          bool
	bgBrush, fieldBrush, selBrush uintptr

	anchorX, anchorY int32 // top centre of the popup
	maxW             int32
	fields           []RECT
	labels           []struct {
		r    RECT
		text string
	}
	header, empty, footer RECT
}

func (u *ui) s(v int) int32 { return int32(v * int(u.dpi) / 96) }

func (u *ui) init(h uintptr) {
	u.hwnd = h
	inst := call(pGetModuleHandleW, 0)
	edit := func(id int, extra uintptr) uintptr {
		e := call(pCreateWindowExW, 0, uintptr(unsafe.Pointer(u16("EDIT"))), 0,
			WS_CHILD|WS_TABSTOP|ES_AUTOHSCROLL|extra, 0, 0, 10, 10, h, uintptr(id), inst, 0)
		u.edits = append(u.edits, e)
		return e
	}
	u.eSearch = edit(idSearch, 0)
	u.eServer = edit(idServer, 0)
	u.eUser = edit(idUser, 0)
	u.ePass = edit(idPass, ES_PASSWORD)
	u.lst = call(pCreateWindowExW, 0, uintptr(unsafe.Pointer(u16("LISTBOX"))), 0,
		WS_CHILD|LBS_NOTIFY|LBS_OWNERDRAWFIXED|LBS_NODATA|LBS_NOINTEGRALHEIGHT, 0, 0, 10, 10, h, idList, inst, 0)
	proc := windows.NewCallback(editProc)
	for _, e := range u.edits {
		u.oldEditProc = call(pSetWindowLongPtrW, e, ^uintptr(3), proc) // GWLP_WNDPROC (-4)
	}
	cue := func(e uintptr, s string) { send(e, EM_SETCUEBANNER, 1, uintptr(unsafe.Pointer(u16(s)))) }
	cue(u.eSearch, "Search secrets, sites and usernames")
	cue(u.eServer, "https://storii.example.com")
	cue(u.ePass, "Master password")
	u.applyTheme()
}

func (u *ui) visible() bool { return call(pIsWindowVisible, u.hwnd) != 0 }

// open places the popup on the monitor with the mouse pointer and shows it.
func (u *ui) open(m mode) {
	var pt POINT
	call(pGetCursorPos, uintptr(unsafe.Pointer(&pt)))
	mon := call(pMonitorFromPoint, uintptr(pt.X)|uintptr(pt.Y)<<32, 2) // MONITOR_DEFAULTTONEAREST
	mi := MONITORINFO{}
	mi.Size = uint32(unsafe.Sizeof(mi))
	call(pGetMonitorInfoW, mon, uintptr(unsafe.Pointer(&mi)))
	w := mi.Work
	u.anchorX = w.Left + (w.Right-w.Left)/2
	u.anchorY = w.Top + (w.Bottom-w.Top)*22/100
	// Move there first, so the window takes that monitor's DPI before it's laid out.
	call(pSetWindowPos, u.hwnd, 0, uintptr(u.anchorX), uintptr(u.anchorY), 1, 1, SWP_NOZORDER|SWP_NOACTIVATE)
	u.setDPI(uint32(call(pGetDpiForWindow, u.hwnd)))
	u.maxW = w.Right - w.Left - u.s(32)
	u.setMode(m)
	call(pShowWindow, u.hwnd, SW_SHOW)
	call(pSetForegroundWindow, u.hwnd)
	u.focus()
}

func (u *ui) close() { call(pShowWindow, u.hwnd, SW_HIDE) }

func (u *ui) focus() {
	switch u.m {
	case modeSearch:
		call(pSetFocus, u.eSearch)
	case modeUnlock:
		call(pSetFocus, u.ePass)
	case modeLogin:
		switch {
		case windowText(u.eServer) == "":
			call(pSetFocus, u.eServer)
		case windowText(u.eUser) == "":
			call(pSetFocus, u.eUser)
		default:
			call(pSetFocus, u.ePass)
		}
	}
}

func (u *ui) setMode(m mode) {
	u.m = m
	setText(u.ePass, "")
	switch m {
	case modeSearch:
		setText(u.eSearch, u.query)
		send(u.eSearch, EM_SETSEL, 0, ^uintptr(0))
		u.search(true)
	case modeLogin:
		if a.st != nil {
			setText(u.eServer, a.st.Server)
			setText(u.eUser, a.st.Username)
		}
	}
	u.layout()
	if u.visible() {
		u.focus()
	}
}

// refresh redraws after a state change, switching screens if the vault was locked, unlocked or logged out.
func (u *ui) refresh() {
	if !u.visible() {
		return
	}
	if m := a.mode(); m != u.m {
		u.setMode(m)
		return
	}
	if u.m == modeSearch {
		u.search(false)
	}
	for _, e := range []uintptr{u.eServer, u.eUser, u.ePass} {
		enable := uintptr(1)
		if a.busy {
			enable = 0
		}
		call(pEnableWindow, e, enable)
	}
	u.layout()
	if !a.busy && call(pGetFocus) == 0 {
		u.focus()
	}
}

func (u *ui) tick() {
	if u.m == modeSearch {
		for _, r := range u.results {
			if r.Type == vault.TypeTOTP {
				call(pInvalidateRect, u.lst, 0, 0)
				return
			}
		}
	}
}

// search reruns the query. reset selects the first row; otherwise the selected secret stays selected.
func (u *ui) search(reset bool) {
	if a.v == nil {
		u.results = nil
		return
	}
	sel := ""
	if i := u.selected(); !reset && i >= 0 {
		sel = u.results[i].ID
	}
	u.results = quick.Search(a.v, u.query, a.recent)
	send(u.lst, LB_SETCOUNT, uintptr(len(u.results)), 0)
	idx := 0
	for i, r := range u.results {
		if r.ID == sel {
			idx = i
		}
	}
	if len(u.results) > 0 {
		send(u.lst, LB_SETCURSEL, uintptr(idx), 0)
	}
	call(pInvalidateRect, u.lst, 0, 1)
}

func (u *ui) selected() int {
	i := int(int32(send(u.lst, LB_GETCURSEL, 0, 0)))
	if i < 0 || i >= len(u.results) {
		return -1
	}
	return i
}

func (u *ui) move(by int) {
	if len(u.results) == 0 {
		return
	}
	i := min(max(u.selected()+by, 0), len(u.results)-1)
	send(u.lst, LB_SETCURSEL, uintptr(i), 0)
	call(pInvalidateRect, u.hwnd, uintptr(unsafe.Pointer(&u.footer)), 0)
}

func (u *ui) layout() {
	w := min(u.s(popupWidth), u.maxW)
	x0, x1 := u.s(pad), w-u.s(pad)
	y := u.s(pad)
	u.fields = u.fields[:0]
	u.labels = u.labels[:0]
	u.header, u.empty = RECT{}, RECT{}
	show := map[uintptr]bool{}
	field := func(e uintptr, label string) {
		if label != "" {
			u.labels = append(u.labels, struct {
				r    RECT
				text string
			}{RECT{x0, y, x1, y + u.s(labelH)}, label})
			y += u.s(labelH)
		}
		r := RECT{x0, y, x1, y + u.s(fieldH)}
		u.fields = append(u.fields, r)
		// A single-line edit draws its text at the top: centre the control in the field.
		eh := u.s(22)
		ins := u.s(4)
		call(pSetWindowPos, e, 0, uintptr(r.Left+ins), uintptr(r.Top+(r.Bottom-r.Top-eh)/2),
			uintptr(r.Right-r.Left-2*ins), uintptr(eh), SWP_NOZORDER|SWP_NOACTIVATE)
		show[e] = true
		y = r.Bottom + u.s(gap)
	}
	switch u.m {
	case modeSearch:
		field(u.eSearch, "")
		rows := min(len(u.results), maxRows)
		if rows == 0 {
			u.empty = RECT{x0, y, x1, y + u.s(rowH)}
			y = u.empty.Bottom
		} else {
			h := int32(rows) * u.s(rowH)
			call(pSetWindowPos, u.lst, 0, uintptr(x0), uintptr(y), uintptr(x1-x0), uintptr(h), SWP_NOZORDER|SWP_NOACTIVATE)
			show[u.lst] = true
			y += h
		}
	case modeUnlock:
		u.header = RECT{x0, y, x1, y + u.s(headerH)}
		y = u.header.Bottom + u.s(gap)
		field(u.ePass, "")
	case modeLogin:
		u.header = RECT{x0, y, x1, y + u.s(headerH)}
		y = u.header.Bottom + u.s(gap)
		field(u.eServer, "Server")
		field(u.eUser, "Username")
		field(u.ePass, "Master password")
	}
	u.footer = RECT{0, y + u.s(4), w, y + u.s(4) + u.s(footerH)}
	h := u.footer.Bottom
	for _, c := range append(slicesClone(u.edits), u.lst) {
		sw := uintptr(SW_HIDE)
		if show[c] {
			sw = SW_SHOW
		}
		call(pShowWindow, c, sw)
	}
	call(pSetWindowPos, u.hwnd, 0, uintptr(u.anchorX-w/2), uintptr(u.anchorY), uintptr(w), uintptr(h), SWP_NOZORDER|SWP_NOACTIVATE)
	call(pInvalidateRect, u.hwnd, 0, 1)
}

func slicesClone(s []uintptr) []uintptr { return append([]uintptr(nil), s...) }

func (u *ui) setDPI(dpi uint32) {
	if dpi == 0 {
		dpi = 96
	}
	if dpi == u.dpi && u.fUI != 0 {
		return
	}
	u.dpi = dpi
	for _, f := range []uintptr{u.fBig, u.fUI, u.fBold, u.fSmall} {
		if f != 0 {
			call(pDeleteObject, f)
		}
	}
	font := func(pt int, weight int) uintptr {
		return call(pCreateFontW, uintptr(-int32(pt*int(dpi)/72)), 0, 0, 0, uintptr(weight), 0, 0, 0, 1, 0, 0, 5, 0,
			uintptr(unsafe.Pointer(u16("Segoe UI"))))
	}
	u.fBig, u.fUI, u.fBold, u.fSmall = font(12, FW_NORMAL), font(10, FW_NORMAL), font(10, FW_SEMIBOLD), font(9, FW_NORMAL)
	for _, e := range u.edits {
		f := u.fUI
		if e == u.eSearch {
			f = u.fBig
		}
		send(e, WM_SETFONT, f, 0)
		m := uintptr(u.s(6))
		send(e, EM_SETMARGINS, EC_LEFTMARGIN|EC_RIGHTMARGIN, m|m<<16)
	}
	send(u.lst, LB_SETITEMHEIGHT, 0, uintptr(u.s(rowH)))
}

// applyTheme follows the Windows light/dark app setting.
func (u *ui) applyTheme() {
	u.dark = false
	if k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`, registry.QUERY_VALUE); err == nil {
		v, _, err := k.GetIntegerValue("AppsUseLightTheme")
		u.dark = err == nil && v == 0
		k.Close()
	}
	u.t = lightTheme
	if u.dark {
		u.t = darkTheme
	}
	for _, b := range []uintptr{u.bgBrush, u.fieldBrush, u.selBrush} {
		if b != 0 {
			call(pDeleteObject, b)
		}
	}
	u.bgBrush = call(pCreateSolidBrush, rgb(u.t.bg))
	u.fieldBrush = call(pCreateSolidBrush, rgb(u.t.field))
	u.selBrush = call(pCreateSolidBrush, rgb(u.t.accent))
	dark := uint32(0)
	if u.dark {
		dark = 1
	}
	corner := uint32(DWMWCP_ROUND)
	border := uint32(rgb(u.t.line))
	call(pDwmSetWindowAttribute, u.hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, uintptr(unsafe.Pointer(&dark)), 4)
	call(pDwmSetWindowAttribute, u.hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, uintptr(unsafe.Pointer(&corner)), 4)
	call(pDwmSetWindowAttribute, u.hwnd, DWMWA_BORDER_COLOR, uintptr(unsafe.Pointer(&border)), 4)
	call(pInvalidateRect, u.hwnd, 0, 1)
}

// handle covers the popup's own messages; ok=false falls through to DefWindowProc.
func (u *ui) handle(msg uint32, w, l uintptr) (uintptr, bool) {
	switch msg {
	case WM_ERASEBKGND:
		return 1, true
	case WM_PAINT:
		u.paint()
		return 0, true
	case WM_CTLCOLOREDIT, WM_CTLCOLORSTATIC:
		call(pSetTextColor, w, rgb(u.t.text))
		call(pSetBkColor, w, rgb(u.t.field))
		return u.fieldBrush, true
	case WM_CTLCOLORLISTBOX:
		return u.bgBrush, true
	case WM_MEASUREITEM:
		mi := (*MEASUREITEMSTRUCT)(unsafe.Pointer(l))
		mi.ItemHeight = uint32(u.s(rowH))
		return 1, true
	case WM_DRAWITEM:
		u.drawRow((*DRAWITEMSTRUCT)(unsafe.Pointer(l)))
		return 1, true
	case WM_COMMAND:
		id, code := loword(w), hiword(w)
		switch {
		case id == idSearch && code == EN_CHANGE:
			if q := windowText(u.eSearch); q != u.query {
				u.query, u.status = q, ""
				u.search(true)
				u.layout()
			}
		case id == idList && code == LBN_SELCHANGE:
			call(pInvalidateRect, u.hwnd, uintptr(unsafe.Pointer(&u.footer)), 0)
			call(pSetFocus, u.eSearch)
		case id == idList && code == LBN_DBLCLK:
			u.enter(0)
		}
		return 0, true
	case WM_DPICHANGED:
		u.setDPI(hiword(w))
		u.layout()
		return 0, true
	}
	return 0, false
}

func (u *ui) enter(action rune) {
	if a.busy {
		return
	}
	switch u.m {
	case modeSearch:
		if i := u.selected(); i >= 0 {
			a.act(u.results[i], action)
		}
	case modeUnlock:
		pw := windowText(u.ePass)
		setText(u.ePass, "")
		a.unlock(pw)
	case modeLogin:
		pw := windowText(u.ePass)
		setText(u.ePass, "")
		a.login(strings.TrimSpace(windowText(u.eServer)), strings.TrimSpace(windowText(u.eUser)), pw)
	}
}

// editProc subclasses the edits for the popup's keys: arrows move the selection, Enter acts, Esc closes, Tab moves
// between fields, Ctrl+T/Ctrl+O/Ctrl+A/Ctrl+Backspace.
func editProc(h, msg, w, l uintptr) uintptr {
	u := &a.ui
	switch uint32(msg) {
	case WM_KEYDOWN:
		ctrl, shift := keyDown(VK_CONTROL), keyDown(VK_SHIFT)
		switch {
		case w == VK_ESCAPE:
			if u.m == modeSearch && u.query != "" {
				setText(u.eSearch, "")
			} else {
				a.hide(true)
			}
			return 0
		case w == VK_RETURN:
			switch {
			case shift:
				u.enter('u')
			case ctrl:
				u.enter('t')
			default:
				u.enter(0)
			}
			return 0
		case w == VK_TAB:
			u.tab(h, shift)
			return 0
		case u.m == modeSearch && w == VK_DOWN:
			u.move(1)
			return 0
		case u.m == modeSearch && w == VK_UP:
			u.move(-1)
			return 0
		case u.m == modeSearch && w == VK_NEXT:
			u.move(maxRows)
			return 0
		case u.m == modeSearch && w == VK_PRIOR:
			u.move(-maxRows)
			return 0
		case ctrl && w == 'A':
			send(h, EM_SETSEL, 0, ^uintptr(0))
			return 0
		case ctrl && w == 'T' && u.m == modeSearch:
			u.enter('t')
			return 0
		case ctrl && w == 'O' && u.m == modeSearch:
			u.enter('o')
			return 0
		case ctrl && w == 'U' && u.m == modeSearch:
			u.enter('u')
			return 0
		}
	case WM_CHAR:
		switch w {
		case '\r', '\t', 0x1b, 0x01, 0x0f, 0x14, 0x15, 0x0a: // handled in WM_KEYDOWN; swallow the beep
			return 0
		case 0x7f: // Ctrl+Backspace: delete the word before the cursor
			deleteWord(h)
			return 0
		}
	}
	return call(pCallWindowProcW, u.oldEditProc, h, msg, w, l)
}

func (u *ui) tab(from uintptr, back bool) {
	var order []uintptr
	switch u.m {
	case modeLogin:
		order = []uintptr{u.eServer, u.eUser, u.ePass}
	default:
		return
	}
	for i, e := range order {
		if e == from {
			n := len(order)
			next := order[(i+1)%n]
			if back {
				next = order[(i+n-1)%n]
			}
			call(pSetFocus, next)
			send(next, EM_SETSEL, 0, ^uintptr(0))
			return
		}
	}
}

func deleteWord(h uintptr) {
	var start, end uint32
	send(h, EM_GETSEL, uintptr(unsafe.Pointer(&start)), uintptr(unsafe.Pointer(&end)))
	if start != end {
		send(h, EM_REPLACESEL, 1, uintptr(unsafe.Pointer(u16(""))))
		return
	}
	text := windows.StringToUTF16(windowText(h))
	text = text[:len(text)-1]
	i := int(start)
	for i > 0 && text[i-1] == ' ' {
		i--
	}
	for i > 0 && text[i-1] != ' ' {
		i--
	}
	send(h, EM_SETSEL, uintptr(i), uintptr(start))
	send(h, EM_REPLACESEL, 1, uintptr(unsafe.Pointer(u16(""))))
}

// Painting.

func (u *ui) text(hdc uintptr, s string, r RECT, font uintptr, color uint32, flags uintptr) {
	call(pSelectObject, hdc, font)
	call(pSetTextColor, hdc, rgb(color))
	p, _ := windows.UTF16FromString(s)
	call(pDrawTextW, hdc, uintptr(unsafe.Pointer(&p[0])), ^uintptr(0), uintptr(unsafe.Pointer(&r)),
		flags|DT_SINGLELINE|DT_NOPREFIX|DT_END_ELLIPSIS)
}

func (u *ui) paint() {
	var ps PAINTSTRUCT
	hdc := call(pBeginPaint, u.hwnd, uintptr(unsafe.Pointer(&ps)))
	defer call(pEndPaint, u.hwnd, uintptr(unsafe.Pointer(&ps)))
	var rc RECT
	call(pGetClientRect, u.hwnd, uintptr(unsafe.Pointer(&rc)))
	call(pFillRect, hdc, uintptr(unsafe.Pointer(&rc)), u.bgBrush)
	call(pSetBkMode, hdc, TRANSPARENT)

	pen := call(pCreatePen, 0, 1, rgb(u.t.line))
	oldPen := call(pSelectObject, hdc, pen)
	oldBrush := call(pSelectObject, hdc, u.fieldBrush)
	rad := uintptr(u.s(10))
	for _, f := range u.fields {
		call(pRoundRect, hdc, uintptr(f.Left), uintptr(f.Top), uintptr(f.Right), uintptr(f.Bottom), rad, rad)
	}
	call(pSelectObject, hdc, oldBrush)
	// Footer separator.
	sep := RECT{0, u.footer.Top, u.footer.Right, u.footer.Top + 1}
	lineBrush := call(pCreateSolidBrush, rgb(u.t.line))
	call(pFillRect, hdc, uintptr(unsafe.Pointer(&sep)), lineBrush)
	call(pDeleteObject, lineBrush)
	call(pSelectObject, hdc, oldPen)
	call(pDeleteObject, pen)

	for _, lb := range u.labels {
		u.text(hdc, lb.text, lb.r, u.fSmall, u.t.muted, DT_LEFT|DT_VCENTER)
	}
	if u.header.Bottom > 0 {
		top, bottom := u.header, u.header
		top.Bottom = top.Top + (top.Bottom-top.Top)/2 + u.s(2)
		bottom.Top = top.Bottom
		title, sub := "Log in to storii", "Your master password never leaves this PC. To create an account, use another storii app or the CLI."
		if u.m == modeUnlock {
			title, sub = "storii is locked", a.st.Username+" on "+strings.TrimPrefix(a.st.Server, "https://")
		}
		u.text(hdc, title, top, u.fBold, u.t.text, DT_LEFT|DT_VCENTER)
		u.text(hdc, sub, bottom, u.fSmall, u.t.muted, DT_LEFT|DT_VCENTER)
	}
	if u.empty.Bottom > 0 {
		msg := "No matches"
		if u.query == "" {
			msg = "Your vault is empty. Add secrets in the storii apps or with `storii add`."
		}
		u.text(hdc, msg, u.empty, u.fUI, u.t.muted, DT_LEFT|DT_VCENTER)
	}
	f := u.footer
	f.Left, f.Right = u.s(pad), f.Right-u.s(pad)
	color, msg := u.t.muted, u.hints()
	if u.status != "" {
		msg = u.status
		if u.statusErr {
			color = u.t.danger
		}
	} else if a.expired && u.m != modeLogin {
		msg, color = "Session expired: log in again from the tray menu. Showing the local copy.", u.t.danger
	}
	u.text(hdc, msg, f, u.fSmall, color, DT_LEFT|DT_VCENTER)
}

func (u *ui) hints() string {
	switch u.m {
	case modeLogin, modeUnlock:
		return "Enter to continue · Esc to close"
	}
	i := u.selected()
	if i < 0 {
		return "Esc to close"
	}
	r := u.results[i]
	parts := []string{"Enter copies the " + quick.What(r.Type)}
	switch r.Type {
	case vault.TypePassword:
		parts = append(parts, "Shift+Enter username")
	case vault.TypeTOTP:
		parts = append(parts, "Shift+Enter account")
	case vault.TypeAPIKey:
		parts = append(parts, "Shift+Enter key id")
	}
	if r.Has2FA {
		parts = append(parts, "Ctrl+Enter 2FA code")
	}
	if r.URL != "" {
		parts = append(parts, "Ctrl+O open")
	}
	return strings.Join(parts, " · ")
}

func (u *ui) drawRow(d *DRAWITEMSTRUCT) {
	if int32(d.ItemID) < 0 || int(d.ItemID) >= len(u.results) {
		return
	}
	r := u.results[d.ItemID]
	sel := d.ItemState&ODS_SELECTED != 0
	rc := d.Rc
	call(pFillRect, d.Hdc, uintptr(unsafe.Pointer(&rc)), u.bgBrush)
	text, muted := u.t.text, u.t.muted
	if sel {
		pen := call(pCreatePen, 5, 0, 0) // PS_NULL
		oldPen := call(pSelectObject, d.Hdc, pen)
		oldBrush := call(pSelectObject, d.Hdc, u.selBrush)
		rad := uintptr(u.s(10))
		call(pRoundRect, d.Hdc, uintptr(rc.Left), uintptr(rc.Top+1), uintptr(rc.Right+1), uintptr(rc.Bottom), rad, rad)
		call(pSelectObject, d.Hdc, oldBrush)
		call(pSelectObject, d.Hdc, oldPen)
		call(pDeleteObject, pen)
		text, muted = u.t.accentText, u.t.accentText
	}
	call(pSetBkMode, d.Hdc, TRANSPARENT)
	in := RECT{rc.Left + u.s(12), rc.Top, rc.Right - u.s(12), rc.Bottom}
	mid := in.Top + (in.Bottom-in.Top)/2

	right := quick.TypeLabel(r.Type)
	rightFont := u.fSmall
	if r.Type == vault.TypeTOTP {
		if it, ok := a.v.Items[r.ID]; ok {
			code, left := quick.TOTPStatus(it, time.Now())
			right, rightFont = code+"  "+itoa(left)+"s", u.fBold
		}
	} else if r.Has2FA {
		right += " + 2fa"
	}
	rw := u.s(130)
	u.text(d.Hdc, right, RECT{in.Right - rw, in.Top, in.Right, in.Bottom}, rightFont, muted, DT_RIGHT|DT_VCENTER)
	in.Right -= rw + u.s(8)
	if r.Subtitle == "" {
		u.text(d.Hdc, r.Name, in, u.fBold, text, DT_LEFT|DT_VCENTER)
		return
	}
	u.text(d.Hdc, r.Name, RECT{in.Left, in.Top + u.s(5), in.Right, mid + u.s(1)}, u.fBold, text, DT_LEFT|DT_VCENTER)
	u.text(d.Hdc, r.Subtitle, RECT{in.Left, mid + u.s(1), in.Right, in.Bottom - u.s(5)}, u.fSmall, muted, DT_LEFT|DT_VCENTER)
}

func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return itoa(n/10) + string(rune('0'+n%10))
}
