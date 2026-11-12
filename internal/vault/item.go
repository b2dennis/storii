package vault

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"
)

// Item kinds, stored inside the ciphertext.
const (
	KindSecret  = "secret"
	KindContext = "context"
)

// Secret types.
const (
	TypePassword = "password"
	TypeTOTP     = "totp"
	TypeAPIKey   = "api_key"
	TypeNote     = "note"
	TypeCard     = "card" // fields: FieldCardholder, FieldNumber, FieldExpiry, FieldCVC
	// TypePasskey is a WebAuthn credential created by a storii client (the browser extension): fields credential_id,
	// rp_id, user_handle (base64url), user_name, user_display_name and private_key (PKCS#8 P-256, base64url).
	TypePasskey = "passkey"
)

// Field names per type. Unknown fields are kept and shown as text.
const (
	FieldUsername  = "username"
	FieldPassword  = "password"
	FieldSecret    = "secret" // TOTP base32 secret
	FieldIssuer    = "issuer"
	FieldAccount   = "account"
	FieldAlgorithm = "algorithm"
	FieldDigits    = "digits"
	FieldPeriod    = "period"
	FieldKey       = "key" // API key
	FieldKeyID     = "key_id"
)

// Context types.
const (
	ContextWebsite = "website"
	ContextApp     = "app"
	ContextOther   = "other"
)

var SecretTypes = []string{TypePassword, TypeTOTP, TypeAPIKey, TypeNote, TypeCard, TypePasskey}

// Item is the decrypted JSON of one stored item: either a secret or a context.
type Item struct {
	Kind string `json:"kind"`
	Name string `json:"name"`

	// Secrets.
	Type     string            `json:"type,omitempty"`
	Contexts []string          `json:"contexts,omitempty"` // context item ids
	Fields   map[string]string `json:"fields,omitempty"`
	Custom   []CustomField     `json:"custom,omitempty"`

	// Contexts.
	ContextType     string   `json:"context_type,omitempty"`
	URLs            []string `json:"urls,omitempty"`
	AndroidPackages []string `json:"android_packages,omitempty"`

	Notes     string    `json:"notes,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type CustomField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Hidden bool   `json:"hidden,omitempty"`
}

func (it Item) Validate() error {
	if strings.TrimSpace(it.Name) == "" {
		return errors.New("name is required")
	}
	switch it.Kind {
	case KindSecret:
		if !slices.Contains(SecretTypes, it.Type) {
			return errors.New("unknown secret type " + it.Type)
		}
		if it.Type == TypeTOTP {
			if _, err := TOTPFromFields(it.Fields); err != nil {
				return err
			}
		}
	case KindContext:
		switch it.ContextType {
		case ContextWebsite, ContextApp, ContextOther:
		default:
			return errors.New("unknown context type " + it.ContextType)
		}
	default:
		return errors.New("unknown item kind " + it.Kind)
	}
	return nil
}

// Field returns a field value or "".
func (it Item) Field(name string) string { return it.Fields[name] }

func (it Item) Marshal() ([]byte, error) { return json.Marshal(it) }

func UnmarshalItem(b []byte) (Item, error) {
	var it Item
	err := json.Unmarshal(b, &it)
	return it, err
}

// SecretValue is what "copy" means for each type: the password, the current code, the key or the note.
func (it Item) SecretValue(now time.Time) (string, error) {
	switch it.Type {
	case TypePassword:
		return it.Field(FieldPassword), nil
	case TypeTOTP:
		t, err := TOTPFromFields(it.Fields)
		if err != nil {
			return "", err
		}
		return t.Code(now), nil
	case TypeAPIKey:
		return it.Field(FieldKey), nil
	case TypeCard:
		return CardDigits(it.Field(FieldNumber)), nil
	case TypePasskey:
		return "", errors.New("a passkey can't be copied: sites ask storii for it when you sign in")
	default:
		return it.Notes, nil
	}
}
