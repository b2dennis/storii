package main

// storii as a Windows passkey provider (a "plugin authenticator", Windows 11 25H2+). Windows activates the COM class
// clsidStorii in this process (the sparse package from packaging/windows maps it to storii-tray.exe) and calls
// IPluginAuthenticator on COM worker threads. Those calls block until the user is done, so they hand everything that
// touches the app's state to the UI thread with onUI and wait.

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/b2dennis/storii/internal/client"
	"github.com/b2dennis/storii/internal/passkey"
	"github.com/b2dennis/storii/internal/vault"
)

const (
	unlockWait  = 3 * time.Minute
	pluginArg   = "-PluginActivated" // COM starts the exe with this (AppxManifest.xml)
	settingsTip = "Turn storii on in Settings > Accounts > Passkeys > Advanced options."
)

// The rounded keyhole from assets/make_icons.py.
const logoSVG = `<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 100 100">` +
	`<rect width="100" height="100" rx="22" fill="#5856d6"/>` +
	`<circle cx="50" cy="42" r="13" fill="#fff"/><polygon points="45.5,45 54.5,45 59.4,74 40.6,74" fill="#fff"/></svg>`

// A COM object: what COM sees is a pointer to the vtable pointer. Both are static, so AddRef and Release are no-ops.
type comObject struct{ vtbl *uintptr }

var (
	factoryVtbl [5]uintptr
	authVtbl    [7]uintptr
	factoryObj  comObject
	authObj     comObject

	opsMu sync.Mutex
	ops   = map[windows.GUID]*operation{}

	credsMu sync.Mutex // serialises updates of Windows' credential cache
)

type operation struct {
	id        windows.GUID
	cancelled bool // under opsMu
}

func (o *operation) isCancelled() bool {
	opsMu.Lock()
	defer opsMu.Unlock()
	return o.cancelled
}

func beginOp(id windows.GUID) *operation {
	opsMu.Lock()
	defer opsMu.Unlock()
	o := &operation{id: id}
	ops[id] = o
	return o
}

func endOp(o *operation) {
	opsMu.Lock()
	defer opsMu.Unlock()
	if ops[o.id] == o {
		delete(ops, o.id)
	}
}

// onUI runs f on the UI thread and waits for its result.
func onUI[T any](f func() T) T {
	ch := make(chan T, 1)
	a.post(func() { ch <- f() })
	return <-ch
}

// passkeysReady reports whether Windows can use storii for passkeys at all: the API exists and storii runs with
// its package identity.
func passkeysReady() bool { return webauthnAvailable() && hasPackageIdentity() }

// startPasskeyServer registers the COM class, in a thread of its own in the multithreaded apartment so that calls
// arrive on COM's worker threads and never wait for the UI thread's message loop.
func startPasskeyServer() {
	if !passkeysReady() {
		return
	}
	unknown := []uintptr{windows.NewCallback(comQueryInterface), windows.NewCallback(comAddRef), windows.NewCallback(comRelease)}
	copy(factoryVtbl[:], unknown)
	factoryVtbl[3] = windows.NewCallback(factoryCreateInstance)
	factoryVtbl[4] = windows.NewCallback(factoryLockServer)
	copy(authVtbl[:], unknown)
	authVtbl[3] = windows.NewCallback(authMakeCredential)
	authVtbl[4] = windows.NewCallback(authGetAssertion)
	authVtbl[5] = windows.NewCallback(authCancelOperation)
	authVtbl[6] = windows.NewCallback(authGetLockStatus)
	factoryObj.vtbl = &factoryVtbl[0]
	authObj.vtbl = &authVtbl[0]

	go func() {
		runtime.LockOSThread()
		call(pCoInitializeEx, 0, COINIT_MULTITHREADED)
		call(pCoInitializeSecurity, 0, ^uintptr(0), 0, 0, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IDENTIFY, 0, EOAC_NONE, 0)
		var cookie uint32
		if hr := call(pCoRegisterClassObject, uintptr(unsafe.Pointer(&clsidStorii)), uintptr(unsafe.Pointer(&factoryObj)),
			CLSCTX_LOCAL_SERVER, REGCLS_MULTIPLEUSE, uintptr(unsafe.Pointer(&cookie))); hr != S_OK {
			return
		}
		select {} // keeps this thread, and with it the apartment, alive while the app runs
	}()
}

// IUnknown and IClassFactory.

func comQueryInterface(this, riid, ppv uintptr) uintptr {
	if ppv == 0 || riid == 0 {
		return E_POINTER
	}
	iid := *(*windows.GUID)(unsafe.Pointer(riid))
	ok := iid == iidIUnknown ||
		(this == uintptr(unsafe.Pointer(&factoryObj)) && iid == iidIClassFactory) ||
		(this == uintptr(unsafe.Pointer(&authObj)) && iid == iidIPluginAuthenticator)
	if !ok {
		*(*uintptr)(unsafe.Pointer(ppv)) = 0
		return E_NOINTERFACE
	}
	*(*uintptr)(unsafe.Pointer(ppv)) = this
	return S_OK
}

func comAddRef(this uintptr) uintptr  { return 1 }
func comRelease(this uintptr) uintptr { return 1 }

func factoryCreateInstance(this, outer, riid, ppv uintptr) uintptr {
	if outer != 0 {
		return CLASS_E_NOAGGREGATION
	}
	return comQueryInterface(uintptr(unsafe.Pointer(&authObj)), riid, ppv)
}

func factoryLockServer(this, lock uintptr) uintptr { return S_OK }

// guard turns a panic in a handler into E_FAIL instead of taking the tray down.
func guard(hr *uintptr) {
	if recover() != nil {
		*hr = E_FAIL
	}
}

// verifyRequest checks that Windows signed the request, so another program can't ask storii for passkeys.
func verifyRequest(data, sig []byte) bool {
	var cb uint32
	var pb *byte
	if hr := call(pPluginGetOperationSigningPublicKey, uintptr(unsafe.Pointer(&clsidStorii)), uintptr(unsafe.Pointer(&cb)),
		uintptr(unsafe.Pointer(&pb))); hr != S_OK || pb == nil {
		return false
	}
	key := bytesAt(pb, cb)
	call(pPluginFreePublicKeyResponse, uintptr(unsafe.Pointer(pb)))
	return passkey.VerifyCNG(key, data, sig) == nil
}

func operationRequest(reqp, respp uintptr) (*pluginOperationRequest, *pluginOperationResponse, []byte, uintptr) {
	req := (*pluginOperationRequest)(unsafe.Pointer(reqp))
	resp := (*pluginOperationResponse)(unsafe.Pointer(respp))
	if req == nil || resp == nil || req.RequestType != ctapRequestTypeCBOR || req.CbEncodedRequest == 0 {
		return nil, nil, nil, E_INVALIDARG
	}
	encoded := bytesAt(req.PbEncodedRequest, req.CbEncodedRequest)
	if !verifyRequest(encoded, bytesAt(req.PbRequestSignature, req.CbRequestSignature)) {
		return nil, nil, nil, E_ACCESSDENIED
	}
	return req, resp, encoded, S_OK
}

func credentialIDs(l credentialList) []string {
	if l.Count == 0 || l.Credentials == nil {
		return nil
	}
	var out []string
	for _, c := range unsafe.Slice(l.Credentials, l.Count) {
		if c != nil && c.CbID > 0 {
			out = append(out, passkey.B64(bytesAt(c.PbID, c.CbID)))
		}
	}
	return out
}

// waitUnlocked opens the unlock (or login) window when the vault is locked and waits until the user has unlocked it.
// justUnlocked means the user typed the master password for this request, which also verifies them.
func waitUnlocked(o *operation) (justUnlocked bool, hr uintptr) {
	if onUI(func() bool {
		if a.v != nil {
			a.lastUse = time.Now()
			return true
		}
		a.show()
		return false
	}) {
		return false, S_OK
	}
	start := time.Now()
	for time.Since(start) < unlockWait {
		time.Sleep(250 * time.Millisecond)
		if o.isCancelled() {
			a.post(func() {
				if a.v == nil {
					a.hide(false)
				}
			})
			return false, NTE_USER_CANCELLED
		}
		switch onUI(func() int {
			switch {
			case a.v != nil:
				a.hide(true) // back to the browser
				return 0
			case a.ui.visible() || a.busy:
				return 1
			case time.Since(start) < 2*time.Second:
				a.show() // it lost the focus straight away, behind Windows' passkey dialog
				return 1
			}
			return 2 // the user closed it
		}) {
		case 0:
			return true, S_OK
		case 2:
			return false, NTE_USER_CANCELLED
		}
	}
	a.post(func() { a.hide(false) })
	return false, HR_TIMEOUT
}

// verifyUser asks for Windows Hello. Where Hello isn't set up, a plain confirmation stands in for it (the vault is
// unlocked, as with the extension's prompt).
func verifyUser(hwnd uintptr, tx *windows.GUID, user, hint, confirm string) uintptr {
	req := userVerificationRequest{HWnd: hwnd, TransactionID: tx, UserName: u16(user), DisplayHint: u16(hint)}
	var cb uint32
	var pb *byte
	hr := call(pPluginPerformUserVerification, uintptr(unsafe.Pointer(&req)), uintptr(unsafe.Pointer(&cb)), uintptr(unsafe.Pointer(&pb)))
	runtime.KeepAlive(&req)
	if pb != nil {
		call(pPluginFreeUserVerificationResponse, uintptr(unsafe.Pointer(pb)))
	}
	switch uint32(hr) {
	case S_OK:
		return S_OK
	case NTE_USER_CANCELLED, HR_CANCELLED:
		return NTE_USER_CANCELLED
	}
	// MB_OKCANCEL|MB_ICONQUESTION|MB_SETFOREGROUND|MB_TOPMOST; IDOK
	if call(pMessageBoxW, 0, uintptr(unsafe.Pointer(u16(confirm))), uintptr(unsafe.Pointer(u16("storii"))), 0x1|0x20|0x10000|0x40000) == 1 {
		return S_OK
	}
	return NTE_USER_CANCELLED
}

// MakeCredential: a site asks for a new passkey and the user picked storii.
func authMakeCredential(this, reqp, respp uintptr) (hr uintptr) {
	defer guard(&hr)
	req, resp, encoded, hr := operationRequest(reqp, respp)
	if hr != S_OK {
		return hr
	}
	var d *makeCredentialRequest
	if hr := call(pDecodeMakeCredentialRequest, uintptr(len(encoded)), uintptr(unsafe.Pointer(&encoded[0])), uintptr(unsafe.Pointer(&d))); hr != S_OK || d == nil {
		return orFail(hr)
	}
	defer call(pFreeDecodedMakeCredentialRequest, uintptr(unsafe.Pointer(d)))

	rpID := string(bytesAt(d.PbRPID, d.CbRPID))
	var rpName string
	if d.RP != nil {
		if rpID == "" {
			rpID = str16(d.RP.ID)
		}
		rpName = str16(d.RP.Name)
	}
	hash := bytesAt(d.PbClientDataHash, d.CbClientDataHash)
	if rpID == "" || len(hash) != 32 || d.User == nil {
		return E_INVALIDARG
	}
	user := passkey.User{ID: bytesAt(d.User.PbID, d.User.CbID), Name: str16(d.User.Name), DisplayName: str16(d.User.DisplayName)}
	if p := d.CredentialParameters; p.Count > 0 && p.Parameters != nil {
		if !slices.ContainsFunc(unsafe.Slice(p.Parameters, p.Count), func(c coseParameter) bool { return c.Alg == coseAlgES256 }) {
			return NTE_NOT_SUPPORTED
		}
	}
	exclude := credentialIDs(d.ExcludeList)

	o := beginOp(req.TransactionID)
	defer endOp(o)
	justUnlocked, hr := waitUnlocked(o)
	if hr != S_OK {
		return hr
	}
	if len(exclude) > 0 && onUI(func() bool {
		for _, it := range passkeysFor(a.v, rpID) {
			if slices.Contains(exclude, it.fields[passkey.FieldCredentialID]) {
				return true
			}
		}
		return false
	}) {
		return NTE_EXISTS
	}
	if !justUnlocked {
		who := user.Name
		if who == "" {
			who = user.DisplayName
		}
		if hr := verifyUser(req.HWnd, &req.TransactionID, who, "Save a passkey for "+rpID+" in storii",
			"Save a passkey for "+rpID+" in storii?"); hr != S_OK {
			return hr
		}
	}
	if o.isCancelled() {
		return NTE_USER_CANCELLED
	}
	c, err := passkey.Create(rpID, user)
	if err != nil {
		return E_FAIL
	}
	name := rpName
	if name == "" {
		name = rpID
	}
	if err := savePasskey(name, c.Fields); err != nil {
		a.post(func() { a.balloon("Passkey not saved", err.Error(), true) })
		return E_FAIL
	}
	att := credentialAttestation{Version: credentialAttestationV8, FormatType: u16("none"),
		CbAuthenticatorData: uint32(len(c.AuthenticatorData)), PbAuthenticatorData: ptr(c.AuthenticatorData)}
	var cb uint32
	var pb *byte
	hr = call(pEncodeMakeCredentialResponse, uintptr(unsafe.Pointer(&att)), uintptr(unsafe.Pointer(&cb)), uintptr(unsafe.Pointer(&pb)))
	runtime.KeepAlive(&att)
	runtime.KeepAlive(c.AuthenticatorData)
	if hr != S_OK || pb == nil {
		return orFail(hr)
	}
	resp.CbEncodedResponse, resp.PbEncodedResponse = cb, pb // Windows frees it (CoTaskMem)
	return S_OK
}

// savePasskey writes the new passkey (and a website context for it, when there's none yet) to the server, with a
// copy of the vault so the UI thread's stays untouched, then swaps the result in.
func savePasskey(name string, fields map[string]string) error {
	type snap struct {
		st *client.State
		v  *client.Vault
	}
	s := onUI(func() snap {
		if a.st == nil || a.v == nil {
			return snap{}
		}
		v, err := a.v.Reopen(a.st.Clone())
		if err != nil {
			return snap{}
		}
		return snap{a.st, v}
	})
	if s.v == nil {
		return errors.New("storii was locked meanwhile")
	}
	writes := passkey.Save(name, fields, func(host string) string { return contextFor(s.v.Items, host) }, time.Now().UTC())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := s.v.Put(ctx, writes); err != nil {
		if client.IsUnauthorized(err) {
			return errors.New("your session expired: log in again in storii")
		}
		return errors.New("couldn't reach the storii server: " + err.Error())
	}
	a.post(func() {
		if a.st != s.st {
			a.sync() // a sync or reload landed meanwhile: pull, which brings the new passkey along
			return
		}
		a.st = s.v.State()
		a.saveState()
		if a.v != nil {
			a.v = s.v
			a.passkeysChanged()
		}
	})
	return nil
}

// contextFor is the website context for a host, or "".
func contextFor(items map[string]vault.Item, host string) string {
	ids := make([]string, 0, len(items))
	for id, it := range items {
		if it.Kind == vault.KindContext && it.MatchesContext(host, "") {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return ""
	}
	sort.Strings(ids)
	return ids[0]
}

type storedPasskey struct {
	id, name string
	fields   map[string]string
}

func (p storedPasskey) label() string {
	u := p.fields[passkey.FieldUserName]
	if u == "" {
		u = p.fields[passkey.FieldUserDisplayName]
	}
	if u == "" {
		return p.name
	}
	return u + " (" + p.name + ")"
}

// passkeysFor lists the vault's passkeys for rpID ("" for all), sorted by label.
func passkeysFor(v *client.Vault, rpID string) []storedPasskey {
	if v == nil {
		return nil
	}
	var out []storedPasskey
	for id, it := range v.Items {
		if it.Kind != vault.KindSecret || it.Type != vault.TypePasskey || it.Fields[passkey.FieldCredentialID] == "" {
			continue
		}
		if rpID != "" && !strings.EqualFold(it.Fields[passkey.FieldRPID], rpID) {
			continue
		}
		f := make(map[string]string, len(it.Fields))
		for k, val := range it.Fields {
			f[k] = val
		}
		out = append(out, storedPasskey{id: id, name: it.Name, fields: f})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].label() != out[j].label() {
			return out[i].label() < out[j].label()
		}
		return out[i].id < out[j].id
	})
	return out
}

// GetAssertion: a site asks to sign in with a passkey from storii.
func authGetAssertion(this, reqp, respp uintptr) (hr uintptr) {
	defer guard(&hr)
	req, resp, encoded, hr := operationRequest(reqp, respp)
	if hr != S_OK {
		return hr
	}
	var d *getAssertionRequest
	if hr := call(pDecodeGetAssertionRequest, uintptr(len(encoded)), uintptr(unsafe.Pointer(&encoded[0])), uintptr(unsafe.Pointer(&d))); hr != S_OK || d == nil {
		return orFail(hr)
	}
	defer call(pFreeDecodedGetAssertionRequest, uintptr(unsafe.Pointer(d)))

	rpID := str16(d.RPID)
	if rpID == "" {
		rpID = string(bytesAt(d.PbRPID, d.CbRPID))
	}
	hash := bytesAt(d.PbClientDataHash, d.CbClientDataHash)
	if rpID == "" || len(hash) != 32 {
		return E_INVALIDARG
	}
	allow := credentialIDs(d.AllowList)

	o := beginOp(req.TransactionID)
	defer endOp(o)
	justUnlocked, hr := waitUnlocked(o)
	if hr != S_OK {
		return hr
	}
	cands := onUI(func() []storedPasskey {
		var out []storedPasskey
		for _, p := range passkeysFor(a.v, rpID) {
			if len(allow) == 0 || slices.Contains(allow, p.fields[passkey.FieldCredentialID]) {
				out = append(out, p)
			}
		}
		return out
	})
	if len(cands) == 0 {
		return NTE_NOT_FOUND
	}
	pick := cands[0]
	if len(cands) > 1 {
		i := onUI(func() int { return pickPasskey(cands) })
		if i < 0 {
			return NTE_USER_CANCELLED
		}
		pick = cands[i]
	}
	if !justUnlocked {
		if hr := verifyUser(req.HWnd, &req.TransactionID, pick.fields[passkey.FieldUserName], "Sign in to "+rpID+" with storii",
			"Sign in to "+rpID+" as "+pick.label()+"?"); hr != S_OK {
			return hr
		}
	}
	if o.isCancelled() {
		return NTE_USER_CANCELLED
	}
	as, err := passkey.Assert(pick.fields, hash)
	if err != nil {
		return E_FAIL
	}
	typ := u16("public-key")
	user := userEntity{Version: userEntityV1, CbID: uint32(len(as.UserHandle)), PbID: ptr(as.UserHandle),
		Name: u16(pick.fields[passkey.FieldUserName]), DisplayName: u16(pick.fields[passkey.FieldUserDisplayName])}
	r := getAssertionResponse{
		Assertion: assertion{Version: assertionV6,
			CbAuthenticatorData: uint32(len(as.AuthenticatorData)), PbAuthenticatorData: ptr(as.AuthenticatorData),
			CbSignature: uint32(len(as.Signature)), PbSignature: ptr(as.Signature),
			Credential: credential{Version: credentialV1, CbID: uint32(len(as.CredentialID)), PbID: ptr(as.CredentialID), Type: typ},
			CbUserID:   uint32(len(as.UserHandle)), PbUserID: ptr(as.UserHandle)},
		NumberOfCredentials: 1,
	}
	if len(as.UserHandle) > 0 {
		r.User = &user
	}
	var cb uint32
	var pb *byte
	hr = call(pEncodeGetAssertionResponse, uintptr(unsafe.Pointer(&r)), uintptr(unsafe.Pointer(&cb)), uintptr(unsafe.Pointer(&pb)))
	runtime.KeepAlive(&r)
	runtime.KeepAlive(&user)
	runtime.KeepAlive(&as)
	runtime.KeepAlive(typ)
	if hr != S_OK || pb == nil {
		return orFail(hr)
	}
	resp.CbEncodedResponse, resp.PbEncodedResponse = cb, pb
	a.post(func() { a.lastUse = time.Now() })
	return S_OK
}

// pickPasskey lets the user choose between several passkeys for a site, as a menu at the mouse. -1 when dismissed.
func pickPasskey(cands []storedPasskey) int {
	m := call(pCreatePopupMenu)
	defer call(pDestroyMenu, m)
	call(pAppendMenuW, m, MF_STRING|MF_GRAYED, 0, uintptr(unsafe.Pointer(u16("Sign in with…"))))
	call(pAppendMenuW, m, MF_SEPARATOR, 0, 0)
	for i, c := range cands {
		call(pAppendMenuW, m, MF_STRING, uintptr(i+1), uintptr(unsafe.Pointer(u16(c.label()))))
	}
	var pt POINT
	call(pGetCursorPos, uintptr(unsafe.Pointer(&pt)))
	call(pSetForegroundWindow, a.hwnd)
	cmd := call(pTrackPopupMenu, m, TPM_RIGHTBUTTON|TPM_RETURNCMD, uintptr(pt.X), uintptr(pt.Y), 0, a.hwnd, 0)
	post(a.hwnd, 0, 0, 0)
	if cmd == 0 || int(cmd) > len(cands) {
		return -1
	}
	return int(cmd) - 1
}

func authCancelOperation(this, reqp uintptr) (hr uintptr) {
	defer guard(&hr)
	req := (*pluginCancelOperationRequest)(unsafe.Pointer(reqp))
	if req == nil {
		return E_INVALIDARG
	}
	opsMu.Lock()
	if o := ops[req.TransactionID]; o != nil {
		o.cancelled = true
	}
	opsMu.Unlock()
	return S_OK
}

func authGetLockStatus(this, statusp uintptr) (hr uintptr) {
	defer guard(&hr)
	if statusp == 0 {
		return E_POINTER
	}
	ch := make(chan bool, 1)
	a.post(func() { ch <- a.v != nil })
	status := uint32(pluginLocked)
	select {
	case unlocked := <-ch:
		if unlocked {
			status = pluginUnlocked
		}
	case <-time.After(2 * time.Second):
	}
	*(*uint32)(unsafe.Pointer(statusp)) = status
	return S_OK
}

func orFail(hr uintptr) uintptr {
	if hr == S_OK {
		return E_FAIL
	}
	return hr
}

// Registration and Windows' list of storii passkeys.

func passkeyProviderRegistered() bool {
	if !webauthnAvailable() {
		return false
	}
	var state int32
	return call(pPluginGetAuthenticatorState, uintptr(unsafe.Pointer(&clsidStorii)), uintptr(unsafe.Pointer(&state))) == S_OK
}

// togglePasskeyProvider adds storii to Windows' passkey providers, or removes it.
func (a *app) togglePasskeyProvider() {
	if !hasPackageIdentity() {
		messageBox("To offer its passkeys to Windows, storii has to be registered with Windows first: run " +
			"passkeys\\install-passkeys.ps1 from the storii folder in PowerShell (see the comment at its top).")
		return
	}
	if passkeyProviderRegistered() {
		go func() {
			credsMu.Lock()
			call(pPluginRemoveAllCredentials, uintptr(unsafe.Pointer(&clsidStorii)))
			hr := call(pPluginRemoveAuthenticator, uintptr(unsafe.Pointer(&clsidStorii)))
			credsMu.Unlock()
			a.post(func() {
				a.passkeyKey = ""
				if hr == S_OK {
					a.balloon("Passkeys", "Windows no longer offers storii's passkeys.", false)
				} else {
					a.balloon("Passkeys", "Windows didn't remove storii: "+windows.Errno(hr).Error(), true)
				}
			})
		}()
		return
	}
	var rpID *uint16
	if a.st != nil {
		if u, err := url.Parse(a.st.Server); err == nil && u.Hostname() != "" {
			rpID = u16(u.Hostname())
		}
	}
	go func() {
		logo := u16(base64.StdEncoding.EncodeToString([]byte(logoSVG)))
		info := passkey.AuthenticatorInfo()
		opts := addAuthenticatorOptions{Name: u16("storii"), CLSID: &clsidStorii, PluginRPID: rpID, LightLogoSVG: logo, DarkLogoSVG: logo,
			CbAuthenticatorInfo: uint32(len(info)), PbAuthenticatorInfo: ptr(info)}
		var resp *addAuthenticatorResponse
		hr := call(pPluginAddAuthenticator, uintptr(unsafe.Pointer(&opts)), uintptr(unsafe.Pointer(&resp)))
		runtime.KeepAlive(&opts)
		runtime.KeepAlive(info)
		if resp != nil {
			call(pPluginFreeAddAuthenticatorResponse, uintptr(unsafe.Pointer(resp)))
		}
		a.post(func() {
			if hr != S_OK && uint32(hr) != NTE_EXISTS {
				a.balloon("Passkeys", "Windows didn't add storii: "+windows.Errno(hr).Error(), true)
				return
			}
			a.balloon("storii can now hold passkeys", settingsTip, false)
			a.passkeyKey = ""
			a.passkeysChanged()
		})
	}()
}

// passkeysChanged tells Windows which passkeys storii holds (names and ids only, for its sign-in dialog), when that
// changed since the last time. Called on the UI thread whenever the unlocked vault changes.
func (a *app) passkeysChanged() {
	if a.v == nil || !passkeysReady() {
		return
	}
	list := passkeysFor(a.v, "")
	var key strings.Builder
	for _, p := range list {
		key.WriteString(p.id + "\x00" + p.label() + "\x00" + p.fields[passkey.FieldCredentialID] + "\x00" + p.fields[passkey.FieldRPID] + "\x01")
	}
	if key.String() == a.passkeyKey {
		return
	}
	a.passkeyKey = key.String()
	go func() {
		credsMu.Lock()
		defer credsMu.Unlock()
		if !passkeyProviderRegistered() {
			return
		}
		type keep struct{ id, user []byte }
		var details []pluginCredentialDetails
		var hold []keep
		for _, p := range list {
			id, err := passkey.Unb64(p.fields[passkey.FieldCredentialID])
			if err != nil || len(id) == 0 {
				continue
			}
			user, _ := passkey.Unb64(p.fields[passkey.FieldUserHandle])
			hold = append(hold, keep{id, user})
			details = append(details, pluginCredentialDetails{CbCredentialID: uint32(len(id)), PbCredentialID: ptr(id),
				RPID: u16(p.fields[passkey.FieldRPID]), RPName: u16(p.name), CbUserID: uint32(len(user)), PbUserID: ptr(user),
				UserName: u16(p.fields[passkey.FieldUserName]), UserDisplayName: u16(p.fields[passkey.FieldUserDisplayName])})
		}
		call(pPluginRemoveAllCredentials, uintptr(unsafe.Pointer(&clsidStorii)))
		if len(details) > 0 {
			call(pPluginAddCredentials, uintptr(unsafe.Pointer(&clsidStorii)), uintptr(len(details)), uintptr(unsafe.Pointer(&details[0])))
		}
		runtime.KeepAlive(details)
		runtime.KeepAlive(hold)
	}()
}

// forgetPasskeys empties Windows' list of storii passkeys, on logout.
func (a *app) forgetPasskeys() {
	a.passkeyKey = ""
	if !passkeysReady() {
		return
	}
	go func() {
		credsMu.Lock()
		defer credsMu.Unlock()
		if passkeyProviderRegistered() {
			call(pPluginRemoveAllCredentials, uintptr(unsafe.Pointer(&clsidStorii)))
		}
	}()
}
