package main

// Bindings for the Windows passkey plugin API (webauthn.dll, Windows 11 25H2+): webauthnplugin.h, webauthn.h and
// pluginauthenticator.idl from github.com/microsoft/webauthn. The structs mirror the C layouts on 64-bit Windows.

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	ole32    = windows.NewLazySystemDLL("ole32.dll")
	webauthn = windows.NewLazySystemDLL("webauthn.dll")

	pCoInitializeEx        = ole32.NewProc("CoInitializeEx")
	pCoInitializeSecurity  = ole32.NewProc("CoInitializeSecurity")
	pCoRegisterClassObject = ole32.NewProc("CoRegisterClassObject")
	pCoRevokeClassObject   = ole32.NewProc("CoRevokeClassObject")

	pGetCurrentPackageFullName = kernel32.NewProc("GetCurrentPackageFullName")

	pPluginAddAuthenticator             = webauthn.NewProc("WebAuthNPluginAddAuthenticator")
	pPluginFreeAddAuthenticatorResponse = webauthn.NewProc("WebAuthNPluginFreeAddAuthenticatorResponse")
	pPluginRemoveAuthenticator          = webauthn.NewProc("WebAuthNPluginRemoveAuthenticator")
	pPluginGetAuthenticatorState        = webauthn.NewProc("WebAuthNPluginGetAuthenticatorState")
	pPluginAddCredentials               = webauthn.NewProc("WebAuthNPluginAuthenticatorAddCredentials")
	pPluginRemoveAllCredentials         = webauthn.NewProc("WebAuthNPluginAuthenticatorRemoveAllCredentials")
	pPluginGetOperationSigningPublicKey = webauthn.NewProc("WebAuthNPluginGetOperationSigningPublicKey")
	pPluginFreePublicKeyResponse        = webauthn.NewProc("WebAuthNPluginFreePublicKeyResponse")
	pPluginPerformUserVerification      = webauthn.NewProc("WebAuthNPluginPerformUserVerification")
	pPluginFreeUserVerificationResponse = webauthn.NewProc("WebAuthNPluginFreeUserVerificationResponse")
	pDecodeMakeCredentialRequest        = webauthn.NewProc("WebAuthNDecodeMakeCredentialRequest")
	pFreeDecodedMakeCredentialRequest   = webauthn.NewProc("WebAuthNFreeDecodedMakeCredentialRequest")
	pEncodeMakeCredentialResponse       = webauthn.NewProc("WebAuthNEncodeMakeCredentialResponse")
	pDecodeGetAssertionRequest          = webauthn.NewProc("WebAuthNDecodeGetAssertionRequest")
	pFreeDecodedGetAssertionRequest     = webauthn.NewProc("WebAuthNFreeDecodedGetAssertionRequest")
	pEncodeGetAssertionResponse         = webauthn.NewProc("WebAuthNEncodeGetAssertionResponse")
)

const (
	S_OK                  = 0
	E_NOINTERFACE         = 0x80004002
	E_POINTER             = 0x80004003
	E_FAIL                = 0x80004005
	E_ACCESSDENIED        = 0x80070005
	E_INVALIDARG          = 0x80070057
	CLASS_E_NOAGGREGATION = 0x80040110
	NTE_EXISTS            = 0x8009000F
	NTE_NOT_FOUND         = 0x80090011
	NTE_NOT_SUPPORTED     = 0x80090029
	NTE_USER_CANCELLED    = 0x80090036
	HR_CANCELLED          = 0x800704C7 // HRESULT_FROM_WIN32(ERROR_CANCELLED)
	HR_TIMEOUT            = 0x800705B4 // HRESULT_FROM_WIN32(ERROR_TIMEOUT)

	COINIT_MULTITHREADED            = 0x0
	CLSCTX_LOCAL_SERVER             = 0x4
	REGCLS_MULTIPLEUSE              = 1
	RPC_C_AUTHN_LEVEL_DEFAULT       = 0
	RPC_C_IMP_LEVEL_IDENTIFY        = 2
	EOAC_NONE                       = 0
	APPMODEL_ERROR_NO_PACKAGE       = 15700
	ERROR_INSUFFICIENT_BUFFER       = 122
	pluginLocked                    = 0
	pluginUnlocked                  = 1
	authenticatorStateEnabled       = 1
	ctapRequestTypeCBOR             = 1
	credentialAttestationV8         = 8
	assertionV6                     = 6
	credentialV1                    = 1
	userEntityV1                    = 1
	coseAlgES256              int32 = -7
)

var (
	// The COM class Windows activates for passkey requests; the same id is in packaging/windows/AppxManifest.xml.
	clsidStorii = windows.GUID{Data1: 0xca1b226c, Data2: 0x0328, Data3: 0x4bb2, Data4: [8]byte{0xac, 0xc9, 0x12, 0x7e, 0x5e, 0x4b, 0xec, 0x38}}

	iidIUnknown             = windows.GUID{Data1: 0x00000000, Data2: 0, Data3: 0, Data4: [8]byte{0xc0, 0, 0, 0, 0, 0, 0, 0x46}}
	iidIClassFactory        = windows.GUID{Data1: 0x00000001, Data2: 0, Data3: 0, Data4: [8]byte{0xc0, 0, 0, 0, 0, 0, 0, 0x46}}
	iidIPluginAuthenticator = windows.GUID{Data1: 0xd26bcf6f, Data2: 0xb54c, Data3: 0x43ff, Data4: [8]byte{0x9f, 0x06, 0xd5, 0xbf, 0x14, 0x86, 0x25, 0xf7}}
)

type pluginOperationRequest struct {
	HWnd               uintptr
	TransactionID      windows.GUID
	CbRequestSignature uint32
	PbRequestSignature *byte
	RequestType        int32
	CbEncodedRequest   uint32
	PbEncodedRequest   *byte
}

type pluginOperationResponse struct {
	CbEncodedResponse uint32
	PbEncodedResponse *byte
}

type pluginCancelOperationRequest struct {
	TransactionID      windows.GUID
	CbRequestSignature uint32
	PbRequestSignature *byte
}

type rpEntity struct {
	Version uint32
	ID      *uint16
	Name    *uint16
	Icon    *uint16
}

type userEntity struct {
	Version     uint32
	CbID        uint32
	PbID        *byte
	Name        *uint16
	Icon        *uint16
	DisplayName *uint16
}

type credentialEx struct {
	Version    uint32
	CbID       uint32
	PbID       *byte
	Type       *uint16
	Transports uint32
}

type credentialList struct {
	Count       uint32
	Credentials **credentialEx
}

type coseParameter struct {
	Version uint32
	Type    *uint16
	Alg     int32
}

type coseParameters struct {
	Count      uint32
	Parameters *coseParameter
}

type authenticatorOptions struct {
	Version           uint32
	UP, UV, RequireRK int32
}

type makeCredentialRequest struct {
	Version                uint32
	CbRPID                 uint32
	PbRPID                 *byte
	CbClientDataHash       uint32
	PbClientDataHash       *byte
	RP                     *rpEntity
	User                   *userEntity
	CredentialParameters   coseParameters
	ExcludeList            credentialList
	CbCborExtensionsMap    uint32
	PbCborExtensionsMap    *byte
	Options                *authenticatorOptions
	EmptyPinAuth           int32
	CbPinAuth              uint32
	PbPinAuth              *byte
	HmacSecretExt          int32
	HmacSecretMcExtension  uintptr
	PrfExt                 int32
	CbHmacSecretSaltValues uint32
	PbHmacSecretSaltValues *byte
	CredProtect            uint32
	PinProtocol            uint32
	EnterpriseAttestation  uint32
	CbCredBlobExt          uint32
	PbCredBlobExt          *byte
	LargeBlobKeyExt        int32
	LargeBlobSupport       uint32
	MinPinLengthExt        int32
	CbJSONExt              uint32
	PbJSONExt              *byte
}

type getAssertionRequest struct {
	Version                   uint32
	RPID                      *uint16
	CbRPID                    uint32
	PbRPID                    *byte
	CbClientDataHash          uint32
	PbClientDataHash          *byte
	AllowList                 credentialList
	CbCborExtensionsMap       uint32
	PbCborExtensionsMap       *byte
	Options                   *authenticatorOptions
	EmptyPinAuth              int32
	CbPinAuth                 uint32
	PbPinAuth                 *byte
	HmacSaltExtension         uintptr
	CbHmacSecretSaltValues    uint32
	PbHmacSecretSaltValues    *byte
	PinProtocol               uint32
	CredBlobExt               int32
	LargeBlobKeyExt           int32
	CredLargeBlobOperation    uint32
	CbCredLargeBlobCompressed uint32
	PbCredLargeBlobCompressed *byte
	CredLargeBlobOriginalSize uint32
	CbJSONExt                 uint32
	PbJSONExt                 *byte
}

type extensions struct {
	Count      uint32
	Extensions uintptr
}

type credentialAttestation struct {
	Version                    uint32
	FormatType                 *uint16
	CbAuthenticatorData        uint32
	PbAuthenticatorData        *byte
	CbAttestation              uint32
	PbAttestation              *byte
	AttestationDecodeType      uint32
	AttestationDecode          uintptr
	CbAttestationObject        uint32
	PbAttestationObject        *byte
	CbCredentialID             uint32
	PbCredentialID             *byte
	Extensions                 extensions
	UsedTransport              uint32
	EpAtt                      int32
	LargeBlobSupported         int32
	ResidentKey                int32
	PrfEnabled                 int32
	CbUnsignedExtensionOutputs uint32
	PbUnsignedExtensionOutputs *byte
	HmacSecret                 uintptr
	ThirdPartyPayment          int32
	Transports                 uint32
	CbClientDataJSON           uint32
	PbClientDataJSON           *byte
	CbRegistrationResponseJSON uint32
	PbRegistrationResponseJSON *byte
}

type credential struct {
	Version uint32
	CbID    uint32
	PbID    *byte
	Type    *uint16
}

type assertion struct {
	Version                      uint32
	CbAuthenticatorData          uint32
	PbAuthenticatorData          *byte
	CbSignature                  uint32
	PbSignature                  *byte
	Credential                   credential
	CbUserID                     uint32
	PbUserID                     *byte
	Extensions                   extensions
	CbCredLargeBlob              uint32
	PbCredLargeBlob              *byte
	CredLargeBlobStatus          uint32
	HmacSecret                   uintptr
	UsedTransport                uint32
	CbUnsignedExtensionOutputs   uint32
	PbUnsignedExtensionOutputs   *byte
	CbClientDataJSON             uint32
	PbClientDataJSON             *byte
	CbAuthenticationResponseJSON uint32
	PbAuthenticationResponseJSON *byte
}

type getAssertionResponse struct {
	Assertion                  assertion
	User                       *userEntity
	NumberOfCredentials        uint32
	UserSelected               int32
	CbLargeBlobKey             uint32
	PbLargeBlobKey             *byte
	CbUnsignedExtensionOutputs uint32
	PbUnsignedExtensionOutputs *byte
}

type addAuthenticatorOptions struct {
	Name                *uint16
	CLSID               *windows.GUID
	PluginRPID          *uint16
	LightLogoSVG        *uint16
	DarkLogoSVG         *uint16
	CbAuthenticatorInfo uint32
	PbAuthenticatorInfo *byte
	CSupportedRPIDs     uint32
	SupportedRPIDs      **uint16
}

type addAuthenticatorResponse struct {
	CbOpSignPubKey uint32
	PbOpSignPubKey *byte
}

type pluginCredentialDetails struct {
	CbCredentialID  uint32
	PbCredentialID  *byte
	RPID            *uint16
	RPName          *uint16
	CbUserID        uint32
	PbUserID        *byte
	UserName        *uint16
	UserDisplayName *uint16
}

type userVerificationRequest struct {
	HWnd          uintptr
	TransactionID *windows.GUID
	UserName      *uint16
	DisplayHint   *uint16
}

// bytesAt copies n bytes from C memory.
func bytesAt(p *byte, n uint32) []byte {
	if p == nil || n == 0 {
		return nil
	}
	return append([]byte(nil), unsafe.Slice(p, n)...)
}

func str16(p *uint16) string {
	if p == nil {
		return ""
	}
	return windows.UTF16PtrToString(p)
}

// ptr is a pointer to b's first byte, or nil.
func ptr(b []byte) *byte {
	if len(b) == 0 {
		return nil
	}
	return &b[0]
}

// webauthnAvailable reports whether this Windows has the passkey plugin API.
func webauthnAvailable() bool { return pPluginAddAuthenticator.Find() == nil }

// hasPackageIdentity reports whether storii runs with the identity of its sparse package (install-passkeys.ps1),
// which Windows requires of a passkey provider.
func hasPackageIdentity() bool {
	if pGetCurrentPackageFullName.Find() != nil {
		return false
	}
	var n uint32
	r := call(pGetCurrentPackageFullName, uintptr(unsafe.Pointer(&n)), 0)
	return r != APPMODEL_ERROR_NO_PACKAGE
}
