// storii-tray is storii's Windows tray app: a global hotkey opens a search box over the vault, Enter copies the
// selected secret to the clipboard (kept out of clipboard history) and the clipboard is cleared again after a while.
// It shares the CLI's state file, so logging in with either one works for both.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/b2dennis/storii/internal/client"
	"github.com/b2dennis/storii/internal/quick"
	"github.com/b2dennis/storii/internal/vault"
)

const (
	className = "storii-tray"
	trayID    = 1
	hotkeyID  = 1
	wmTray    = WM_APP + 1
	wmRun     = WM_APP + 2 // run queued functions from background goroutines
	wmShow    = WM_APP + 3 // a second instance asks us to open the search
	timerLock = 1
	timerSync = 2
	timerClip = 3
	timerTick = 4
	syncEvery = 5 * time.Minute
	keepQuery = time.Minute // reopening within this keeps the last search
	runKey    = `Software\Microsoft\Windows\CurrentVersion\Run`
	runValue  = "storii"
)

type mode int

const (
	modeLogin mode = iota
	modeUnlock
	modeSearch
)

type app struct {
	cfg        quick.Config
	cfgPath    string
	statePath  string
	stateMod   time.Time
	st         *client.State // nil when logged out
	v          *client.Vault // nil when locked
	expired    bool          // the server rejected the session; the local copy still works
	syncing    bool
	lastSync   time.Time
	lastUse    time.Time
	hiddenAt   time.Time
	recent     []string
	clipSeq    uint32
	busy       bool // unlocking or logging in
	relogin    bool // the login was asked for although there is a state (expired session)
	hotkeyText string

	hwnd, icon uintptr
	taskbarMsg uint32
	prevFocus  uintptr
	ui         ui
	mu         sync.Mutex
	queue      []func()
}

var a *app

func init() { runtime.LockOSThread() } // all window calls happen on the main thread

func main() {
	if err := run(); err != nil {
		messageBox(err.Error())
		os.Exit(1)
	}
}

func run() error {
	dir, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	a = &app{statePath: filepath.Join(dir, "storii", "state.json"), cfgPath: filepath.Join(dir, "storii", "tray.json")}
	if p := os.Getenv("STORII_STATE"); p != "" {
		a.statePath = p
	}
	if instanceRunning() {
		return nil
	}
	_, statErr := os.Stat(a.cfgPath)
	firstRun := errors.Is(statErr, os.ErrNotExist)
	cfg, cfgErr := quick.LoadConfig(a.cfgPath)
	a.cfg = cfg
	a.loadState()

	call(pSetProcessDpiAwarenessContext, ^uintptr(3)) // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 (-4)
	if err := a.createWindow(); err != nil {
		return err
	}
	a.addTrayIcon()
	hk, _ := quick.ParseHotkey(a.cfg.Hotkey)
	a.hotkeyText = a.cfg.Hotkey
	if !registerHotkey(a.hwnd, hk) {
		a.balloon("Hotkey unavailable", a.cfg.Hotkey+" is used by another app. Change \"hotkey\" in "+a.cfgPath+
			" and restart storii. Until then, click the tray icon.", true)
		a.hotkeyText = ""
	} else if firstRun {
		a.balloon("storii is running", "Press "+a.cfg.Hotkey+" to search your vault.", false)
	}
	if cfgErr != nil {
		a.balloon("Settings not loaded", cfgErr.Error()+". Using the defaults.", true)
	}
	call(pWTSRegisterSessionNotification, a.hwnd, NOTIFY_FOR_THIS_SESSION)
	call(pSetTimer, a.hwnd, timerLock, 30_000, 0)
	call(pSetTimer, a.hwnd, timerSync, uintptr(syncEvery/time.Millisecond), 0)
	a.sync()
	if a.st == nil {
		a.show()
	}
	if len(os.Args) > 1 && os.Args[1] == "--show" {
		a.show()
	}

	var m MSG
	for call(pGetMessageW, uintptr(unsafe.Pointer(&m)), 0, 0, 0) > 0 {
		call(pTranslateMessage, uintptr(unsafe.Pointer(&m)))
		call(pDispatchMessageW, uintptr(unsafe.Pointer(&m)))
	}
	a.lock()
	a.removeTrayIcon()
	return nil
}

// instanceRunning hands over to an already running tray app (which opens its search) and reports whether there was one.
func instanceRunning() bool {
	_, err := windows.CreateMutex(nil, false, u16(`Local\storii-tray`))
	if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return false
	}
	if h := call(pFindWindowW, uintptr(unsafe.Pointer(u16(className))), 0); h != 0 {
		call(pAllowSetForegroundWindow, ^uintptr(0)) // ASFW_ANY
		post(h, wmShow, 0, 0)
	}
	return true
}

// post runs f on the UI thread. Background goroutines use it to hand back results.
func (a *app) post(f func()) {
	a.mu.Lock()
	a.queue = append(a.queue, f)
	a.mu.Unlock()
	post(a.hwnd, wmRun, 0, 0)
}

func (a *app) drain() {
	a.mu.Lock()
	q := a.queue
	a.queue = nil
	a.mu.Unlock()
	for _, f := range q {
		f()
	}
}

// State.

func (a *app) loadState() {
	st, err := client.LoadState(a.statePath)
	if fi, statErr := os.Stat(a.statePath); statErr == nil {
		a.stateMod = fi.ModTime()
	}
	if err != nil {
		a.st = nil
		return
	}
	a.st = st
}

func (a *app) saveState() {
	if a.st == nil {
		return
	}
	if err := a.st.Save(a.statePath); err == nil {
		if fi, err := os.Stat(a.statePath); err == nil {
			a.stateMod = fi.ModTime()
		}
	}
}

// reloadIfChanged picks up a login or logout done with the CLI since we last read or wrote the state file.
func (a *app) reloadIfChanged() {
	fi, err := os.Stat(a.statePath)
	switch {
	case errors.Is(err, os.ErrNotExist) && a.st != nil:
		a.lock()
		a.st = nil
	case err == nil && !fi.ModTime().Equal(a.stateMod):
		old := a.st
		a.loadState()
		if a.st == nil || old == nil || a.st.Username != old.Username || a.st.Server != old.Server {
			a.lock()
		} else if a.v != nil {
			a.reopen()
		}
		if a.st != nil {
			a.expired = false
		}
	}
	a.updateTip()
}

// reopen decrypts the current state with the unlocked vault's keys, after a sync or reload.
func (a *app) reopen() {
	nv, err := a.v.Reopen(a.st)
	if err != nil {
		a.lock()
		a.ui.status, a.ui.statusErr = err.Error(), true
		return
	}
	a.v = nv
}

func (a *app) mode() mode {
	switch {
	case a.st == nil || a.relogin:
		return modeLogin
	case a.v == nil:
		return modeUnlock
	}
	return modeSearch
}

func (a *app) lock() {
	if a.v == nil {
		return
	}
	a.v = nil
	a.clearClip()
	a.ui.query = ""
	if a.ui.visible() {
		a.hide(false)
	}
	a.updateTip()
}

func (a *app) clearClip() {
	clearClipboard(a.hwnd, a.clipSeq)
	a.clipSeq = 0
	call(pKillTimer, a.hwnd, timerClip)
}

func deviceName() string {
	host, _ := os.Hostname()
	if host == "" {
		host = "Windows"
	}
	return "storii tray on " + host
}

// unlock derives the keys in the background (Argon2 takes a moment) and switches to the search.
func (a *app) unlock(pw string) {
	if a.busy || a.st == nil || pw == "" {
		return
	}
	a.busy, a.ui.status, a.ui.statusErr = true, "Unlocking…", false
	a.ui.refresh()
	st := a.st
	go func() {
		v, err := st.Unlock(pw)
		a.post(func() {
			a.busy = false
			if err != nil {
				a.ui.status, a.ui.statusErr = "Wrong master password.", true
				a.ui.refresh()
				return
			}
			if a.st == nil {
				return // logged out meanwhile
			}
			a.v, a.lastUse, a.ui.status = v, time.Now(), ""
			if st != a.st {
				a.reopen()
			}
			if a.v != nil && len(a.v.Undecryptable) > 0 {
				a.ui.status = fmt.Sprintf("%d items could not be decrypted.", len(a.v.Undecryptable))
			}
			a.ui.setMode(a.mode())
			a.updateTip()
			if time.Since(a.lastSync) > time.Minute {
				a.sync()
			}
		})
	}()
}

func (a *app) login(server, user, pw string) {
	if a.busy {
		return
	}
	if server == "" || user == "" || pw == "" {
		a.ui.status, a.ui.statusErr = "Enter the server, your username and your master password.", true
		a.ui.refresh()
		return
	}
	if !strings.Contains(server, "://") {
		server = "https://" + server
	}
	a.busy, a.ui.status, a.ui.statusErr = true, "Logging in…", false
	a.ui.refresh()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		st, v, err := client.Login(ctx, server, user, pw, deviceName())
		a.post(func() {
			a.busy = false
			if err != nil {
				msg := err.Error()
				if client.IsUnauthorized(err) {
					msg = "Wrong username or master password."
				}
				a.ui.status, a.ui.statusErr = msg, true
				a.ui.refresh()
				return
			}
			a.st, a.v, a.expired, a.relogin, a.lastSync, a.lastUse = st, v, false, false, time.Now(), time.Now()
			a.saveState()
			a.ui.status = ""
			a.ui.setMode(a.mode())
			a.updateTip()
		})
	}()
}

func (a *app) logout() {
	if a.st == nil {
		return
	}
	if call(pMessageBoxW, a.hwnd, uintptr(unsafe.Pointer(u16("Log out of storii on this PC? The local copy of your vault is removed; your secrets stay on the server."))),
		uintptr(unsafe.Pointer(u16("storii"))), 0x4|0x20) != 6 { // MB_YESNO|MB_ICONQUESTION, IDYES
		return
	}
	api := a.st.API()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		api.Logout(ctx)
	}()
	a.lock()
	a.st, a.expired = nil, false
	os.Remove(a.statePath)
	a.stateMod = time.Time{}
	a.updateTip()
}

// sync pulls into a copy of the state in the background and swaps it in on the UI thread.
func (a *app) sync() {
	if a.st == nil || a.syncing || a.expired {
		return
	}
	a.syncing = true
	c := a.st.Clone()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err := c.Pull(ctx)
		a.post(func() {
			a.syncing = false
			if a.st == nil || a.st.Username != c.Username || a.st.Server != c.Server {
				return // logged out or switched accounts meanwhile
			}
			if client.IsUnauthorized(err) {
				a.expired = true
				a.updateTip()
				a.ui.refresh()
				return
			}
			if err != nil {
				return // offline: keep using the local copy
			}
			a.lastSync = time.Now()
			a.st = c
			a.saveState()
			if a.v != nil {
				a.reopen()
			}
			a.ui.refresh()
		})
	}()
}

// copyValue copies a secret, remembers it as recently used, and hands the focus back to the previous window.
func (a *app) copyValue(id, value, what string) {
	if value == "" {
		a.ui.status, a.ui.statusErr = "This secret has no "+what+".", true
		a.ui.refresh()
		return
	}
	seq, err := copySecret(a.hwnd, value)
	if err != nil {
		a.ui.status, a.ui.statusErr = err.Error(), true
		a.ui.refresh()
		return
	}
	a.clipSeq = seq
	call(pSetTimer, a.hwnd, timerClip, uintptr(a.cfg.ClearSeconds*1000), 0)
	a.recent = quick.Recent(a.recent, id)
	a.lastUse = time.Now()
	a.setTip(fmt.Sprintf("storii: %s copied, clears in %d s", what, a.cfg.ClearSeconds))
	a.hide(true)
}

// act runs a row action: 0 copies the secret itself, 'u' the username, 't' the related 2FA code, 'o' opens the site.
func (a *app) act(r quick.Result, action rune) {
	it, ok := a.v.Items[r.ID]
	if !ok {
		return
	}
	now := time.Now()
	switch action {
	case 0:
		val, err := it.SecretValue(now)
		if err != nil {
			a.ui.status, a.ui.statusErr = err.Error(), true
			a.ui.refresh()
			return
		}
		a.copyValue(r.ID, val, quick.What(it.Type))
	case 'u':
		what := map[string]string{vault.TypePassword: "username", vault.TypeTOTP: "account", vault.TypeAPIKey: "key id"}[it.Type]
		if what == "" {
			return
		}
		a.copyValue(r.ID, quick.Username(it), what)
	case 't':
		id := r.ID
		if it.Type != vault.TypeTOTP {
			id = quick.Related2FA(a.v, r.ID)
		}
		if id == "" {
			a.ui.status, a.ui.statusErr = "No 2FA secret shares a context with this one.", true
			a.ui.refresh()
			return
		}
		code, err := a.v.Items[id].SecretValue(now)
		if err == nil {
			a.recent = quick.Recent(a.recent, id)
			a.copyValue(r.ID, code, "2FA code")
		}
	case 'o':
		if !strings.HasPrefix(r.URL, "https://") && !strings.HasPrefix(r.URL, "http://") {
			return
		}
		a.hide(false)
		windows.ShellExecute(0, u16("open"), u16(r.URL), nil, nil, SW_SHOW)
	}
}

// Window and tray.

func (a *app) createWindow() error {
	inst := call(pGetModuleHandleW, 0)
	wc := WNDCLASSEXW{
		Style:     CS_DROPSHADOW,
		WndProc:   windows.NewCallback(wndProc),
		Instance:  inst,
		Cursor:    call(pLoadCursorW, 0, IDC_ARROW),
		ClassName: u16(className),
	}
	wc.Size = uint32(unsafe.Sizeof(wc))
	if call(pRegisterClassExW, uintptr(unsafe.Pointer(&wc))) == 0 {
		return errors.New("could not register the window class")
	}
	a.hwnd = call(pCreateWindowExW, WS_EX_TOOLWINDOW|WS_EX_TOPMOST, uintptr(unsafe.Pointer(u16(className))),
		uintptr(unsafe.Pointer(u16("storii"))), WS_POPUP, 0, 0, 100, 100, 0, 0, inst, 0)
	if a.hwnd == 0 {
		return errors.New("could not create the window")
	}
	a.taskbarMsg = uint32(call(pRegisterWindowMessageW, uintptr(unsafe.Pointer(u16("TaskbarCreated")))))
	a.ui.init(a.hwnd)
	return nil
}

func wndProc(h, msg, w, l uintptr) uintptr {
	if a == nil || a.hwnd == 0 {
		return call(pDefWindowProcW, h, msg, w, l)
	}
	switch uint32(msg) {
	case wmRun:
		a.drain()
		return 0
	case wmShow:
		a.show()
		return 0
	case WM_HOTKEY:
		if a.ui.visible() {
			a.hide(true)
		} else {
			a.show()
		}
		return 0
	case wmTray:
		switch loword(l) {
		case NIN_SELECT, NIN_KEYSELECT:
			if !a.ui.visible() && time.Since(a.hiddenAt) > 300*time.Millisecond { // a click that just closed it
				a.show()
			}
		case WM_CONTEXTMENU:
			a.menu()
		}
		return 0
	case WM_TIMER:
		switch w {
		case timerLock:
			if a.v != nil && !a.ui.visible() && time.Since(a.lastUse) > time.Duration(a.cfg.LockMinutes)*time.Minute {
				a.lock()
			}
		case timerSync:
			a.sync()
		case timerClip:
			a.clearClip()
			a.updateTip()
		case timerTick:
			a.ui.tick()
		}
		return 0
	case WM_WTSSESSION_CHANGE:
		if w == WTS_SESSION_LOCK {
			a.lock()
		}
		return 0
	case WM_POWERBROADCAST:
		if w == PBT_APMSUSPEND {
			a.lock()
		}
		return 1
	case WM_ACTIVATE:
		if loword(w) == WA_INACTIVE && a.ui.visible() {
			a.hide(false)
		}
		return 0
	case WM_SETTINGCHANGE:
		if l != 0 && windows.UTF16PtrToString((*uint16)(unsafe.Pointer(l))) == "ImmersiveColorSet" {
			a.ui.applyTheme()
		}
		return 0
	case WM_CLOSE:
		a.hide(false)
		return 0
	case WM_DESTROY:
		call(pPostQuitMessage, 0)
		return 0
	}
	if a.taskbarMsg != 0 && uint32(msg) == a.taskbarMsg { // Explorer restarted
		a.addTrayIcon()
		return 0
	}
	if r, ok := a.ui.handle(uint32(msg), w, l); ok {
		return r
	}
	return call(pDefWindowProcW, h, msg, w, l)
}

func (a *app) show() {
	a.reloadIfChanged()
	if fg := call(pGetForegroundWindow); fg != a.hwnd {
		a.prevFocus = fg
	}
	if time.Since(a.hiddenAt) > keepQuery {
		a.ui.query = ""
	}
	if a.v != nil {
		a.lastUse = time.Now()
		if time.Since(a.lastSync) > time.Minute {
			a.sync()
		}
	}
	a.ui.status = ""
	a.ui.open(a.mode())
	call(pSetTimer, a.hwnd, timerTick, 1000, 0)
}

// hide closes the search. restore hands the focus back to the window that had it, so a paste goes there.
func (a *app) hide(restore bool) {
	if !a.ui.visible() {
		return
	}
	call(pKillTimer, a.hwnd, timerTick)
	a.relogin = false
	a.ui.close()
	a.hiddenAt = time.Now()
	if restore && a.prevFocus != 0 && call(pIsWindow, a.prevFocus) != 0 {
		call(pSetForegroundWindow, a.prevFocus)
	}
}

const (
	cmdSearch = iota + 1
	cmdLock
	cmdSync
	cmdStartup
	cmdSettings
	cmdLogin
	cmdLogout
	cmdQuit
)

func (a *app) menu() {
	m := call(pCreatePopupMenu)
	defer call(pDestroyMenu, m)
	add := func(id int, text string, flags uintptr) {
		call(pAppendMenuW, m, MF_STRING|flags, uintptr(id), uintptr(unsafe.Pointer(u16(text))))
	}
	sep := func() { call(pAppendMenuW, m, MF_SEPARATOR, 0, 0) }
	search := "Search"
	if a.hotkeyText != "" {
		search += "\t" + a.hotkeyText
	}
	add(cmdSearch, search, 0)
	switch {
	case a.st == nil:
		add(cmdLogin, "Log in…", 0)
	case a.v != nil:
		add(cmdLock, "Lock", 0)
	}
	if a.st != nil {
		flags := uintptr(0)
		if a.syncing {
			flags = MF_GRAYED
		}
		label := "Sync now"
		if a.expired {
			label, flags = "Session expired: log in again…", 0
		}
		add(cmdSync, label, flags)
	}
	sep()
	startup := uintptr(0)
	if startsWithWindows() {
		startup = MF_CHECKED
	}
	add(cmdStartup, "Start with Windows", startup)
	add(cmdSettings, "Edit settings (restart to apply)", 0)
	if a.st != nil {
		add(cmdLogout, "Log out ("+a.st.Username+")", 0)
	}
	sep()
	add(cmdQuit, "Quit storii", 0)

	var pt POINT
	call(pGetCursorPos, uintptr(unsafe.Pointer(&pt)))
	call(pSetForegroundWindow, a.hwnd) // or the menu doesn't close when clicking elsewhere
	cmd := call(pTrackPopupMenu, m, TPM_RIGHTBUTTON|TPM_RETURNCMD|TPM_BOTTOMALIGN, uintptr(pt.X), uintptr(pt.Y), 0, a.hwnd, 0)
	post(a.hwnd, 0, 0, 0) // WM_NULL, see the TrackPopupMenu docs
	switch int(cmd) {
	case cmdSearch:
		a.show()
	case cmdLock:
		a.lock()
	case cmdSync:
		if a.expired {
			a.relogin = true // shows the login; the expired state stays usable offline until a login succeeds
			a.show()
			return
		}
		a.sync()
	case cmdStartup:
		setStartWithWindows(!startsWithWindows())
	case cmdSettings:
		windows.ShellExecute(0, u16("open"), u16("notepad.exe"), u16(`"`+a.cfgPath+`"`), nil, SW_SHOW)
	case cmdLogin:
		a.show()
	case cmdLogout:
		a.logout()
	case cmdQuit:
		a.hide(false)
		call(pDestroyWindow, a.hwnd)
	}
}

func (a *app) trayData() NOTIFYICONDATAW {
	d := NOTIFYICONDATAW{Wnd: a.hwnd, ID: trayID}
	d.Size = uint32(unsafe.Sizeof(d))
	return d
}

func (a *app) addTrayIcon() {
	a.icon = loadIcon(call(pGetSystemMetricsForDpi, SM_CXSMICON, uintptr(systemDPI())))
	d := a.trayData()
	d.Flags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP
	d.CallbackMessage = wmTray
	d.Icon = a.icon
	copy(d.Tip[:len(d.Tip)-1], windows.StringToUTF16(a.tip()))
	call(pShellNotifyIconW, NIM_ADD, uintptr(unsafe.Pointer(&d)))
	d.Version = NOTIFYICON_VERSION_4
	call(pShellNotifyIconW, NIM_SETVERSION, uintptr(unsafe.Pointer(&d)))
}

func (a *app) removeTrayIcon() {
	d := a.trayData()
	call(pShellNotifyIconW, NIM_DELETE, uintptr(unsafe.Pointer(&d)))
}

func (a *app) tip() string {
	switch {
	case a.st == nil:
		return "storii: not logged in"
	case a.expired:
		return "storii: session expired, log in again"
	case a.v == nil:
		return "storii: locked"
	}
	return "storii: unlocked"
}

func (a *app) updateTip() { a.setTip(a.tip()) }

func (a *app) setTip(s string) {
	d := a.trayData()
	d.Flags = NIF_TIP | NIF_SHOWTIP
	tip := windows.StringToUTF16(s)
	copy(d.Tip[:len(d.Tip)-1], tip[:min(len(tip), len(d.Tip)-1)])
	call(pShellNotifyIconW, NIM_MODIFY, uintptr(unsafe.Pointer(&d)))
}

func (a *app) balloon(title, text string, warn bool) {
	d := a.trayData()
	d.Flags = NIF_INFO
	copy(d.InfoTitle[:len(d.InfoTitle)-1], windows.StringToUTF16(title))
	t := windows.StringToUTF16(text)
	copy(d.Info[:len(d.Info)-1], t[:min(len(t), len(d.Info)-1)])
	if warn {
		d.InfoFlags = NIIF_WARNING
	}
	call(pShellNotifyIconW, NIM_MODIFY, uintptr(unsafe.Pointer(&d)))
}

func registerHotkey(h uintptr, hk quick.Hotkey) bool {
	mods := uintptr(MOD_NOREPEAT)
	if hk.Ctrl {
		mods |= MOD_CONTROL
	}
	if hk.Alt {
		mods |= MOD_ALT
	}
	if hk.Shift {
		mods |= MOD_SHIFT
	}
	if hk.Win {
		mods |= MOD_WIN
	}
	return call(pRegisterHotKey, h, hotkeyID, mods, uintptr(vkFor(hk.Key))) != 0
}

func vkFor(k string) int {
	switch k {
	case "SPACE":
		return VK_SPACE
	case "ENTER":
		return VK_RETURN
	case "TAB":
		return VK_TAB
	case "INSERT":
		return VK_INSERT
	case "HOME":
		return VK_HOME
	case "END":
		return VK_END
	case "PAGEUP":
		return VK_PRIOR
	case "PAGEDOWN":
		return VK_NEXT
	}
	if len(k) == 1 {
		return int(k[0]) // VK codes for A-Z and 0-9 are their ASCII codes
	}
	var n int
	fmt.Sscanf(k[1:], "%d", &n)
	return VK_F1 + n - 1
}

func startsWithWindows() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue(runValue)
	return err == nil
}

func setStartWithWindows(on bool) {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	if !on {
		k.DeleteValue(runValue)
		return
	}
	if exe, err := os.Executable(); err == nil {
		k.SetStringValue(runValue, `"`+exe+`"`)
	}
}
