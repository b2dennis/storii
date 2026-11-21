package vault

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// testdata/backup.json is a backup every client must open (and the Go test rewrites with -update).
type backupVector struct {
	Comment  string                     `json:"comment"`
	Password string                     `json:"password"`
	Items    map[string]json.RawMessage `json:"items"`
	File     json.RawMessage            `json:"file"`
}

func TestBackupVector(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/backup.json")
	if err != nil {
		t.Fatal(err)
	}
	var v backupVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if *update {
		kdf := KDF{Alg: "argon2id", Salt: "YmFja3VwLXNhbHQtMDAwMQ==", Iterations: 1, MemoryKiB: 16384, Parallelism: 1}
		file, err := SealBackup(v.Password, kdf, v.Items, time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC), bytes.Repeat([]byte{7}, 12))
		if err != nil {
			t.Fatal(err)
		}
		v.File = file
		out, _ := json.MarshalIndent(v, "", "  ")
		if err := os.WriteFile("../../testdata/backup.json", append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if !IsBackup(v.File) || IsBackup([]byte(`{"items":[]}`)) {
		t.Fatal("IsBackup")
	}
	got, err := OpenBackup(v.Password, v.File)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(v.Items) {
		t.Fatalf("%d items, want %d", len(got), len(v.Items))
	}
	for id, want := range v.Items {
		var a, b any
		json.Unmarshal(got[id], &a)
		json.Unmarshal(want, &b)
		if ja, _ := json.Marshal(a); string(ja) != string(must(json.Marshal(b))) {
			t.Errorf("%s: %s, want %s", id, got[id], want)
		}
	}
	if _, err := OpenBackup("wrong", v.File); err != ErrBackupPassword {
		t.Fatalf("wrong password: %v", err)
	}
	// A fresh backup round-trips.
	file, err := SealBackup("other pw", NewKDF(), v.Items, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := OpenBackup("other pw", file); err != nil || len(again) != len(v.Items) {
		t.Fatal(err)
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}
