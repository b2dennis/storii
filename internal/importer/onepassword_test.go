package importer

import (
	"archive/zip"
	"bytes"
	"os"
	"testing"
)

// testdata/import/1password*.json is shared with the Android tests: as export.data on its own, and zipped as .1pux.
func TestOnePasswordSharedCases(t *testing.T) {
	data, err := os.ReadFile("../../testdata/import/1password.json")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("export.data", func(t *testing.T) {
		sharedCases(t, data, "1password-cases.json", KindOnePassword, ParseOnePassword)
	})
	t.Run("1pux", func(t *testing.T) {
		var buf bytes.Buffer
		z := zip.NewWriter(&buf)
		w, _ := z.Create("export.attributes")
		w.Write([]byte(`{"version":3,"description":"1Password Unencrypted Export","createdAt":1700000000}`))
		w, _ = z.Create("export.data")
		w.Write(data)
		z.Close()
		sharedCases(t, buf.Bytes(), "1password-cases.json", KindOnePassword, ParseOnePassword)
	})
	if _, err := ParseOnePassword([]byte("PK\x03\x04garbage")); err == nil {
		t.Error("a broken zip parsed")
	}
}
