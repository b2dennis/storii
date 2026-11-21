package server_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/b2dennis/storii/internal/client"
	"github.com/b2dennis/storii/internal/server"
	"github.com/b2dennis/storii/internal/vault"
)

func TestSharing(t *testing.T) {
	e := newEnv(t, server.Config{Registration: true})
	ctx := context.Background()
	stA, a, err := client.Register(ctx, e.url, "alice", "Correct-Horse-42", "a")
	if err != nil {
		t.Fatal(err)
	}
	stB, b, err := client.Register(ctx, e.url, "bob", "Battery-Staple-7", "b")
	if err != nil {
		t.Fatal(err)
	}
	_, c, err := client.Register(ctx, e.url, "carol", "Tr0ub4dor-and-3", "c")
	if err != nil {
		t.Fatal(err)
	}

	// Bob hasn't set up sharing yet: he can't be added, and Alice can't look up a key.
	if _, _, _, err := a.MemberKey(ctx, "bob"); err == nil {
		t.Fatal("a user without keys has no key to hand out")
	}
	for _, v := range []*client.Vault{b, c} {
		if err := v.SetupSharing(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if code, _ := raw(t, http.MethodPut, e.url+"/api/v2/account/keys", stB.Token,
		map[string]string{"public_key": stB.PublicKey, "sealed_private_key": stB.SealedPrivateKey}); code != http.StatusOK {
		t.Fatalf("setting the same keys again is a no-op, got %d", code)
	}
	if code, _ := raw(t, http.MethodPut, e.url+"/api/v2/account/keys", stB.Token,
		map[string]string{"public_key": c.State().PublicKey, "sealed_private_key": stB.SealedPrivateKey}); code != http.StatusConflict {
		t.Fatalf("keys are set once, got %d", code)
	}

	sh, err := a.CreateShare(ctx, "Family")
	if err != nil {
		t.Fatal(err)
	}
	if !sh.Mine || sh.Name != "Family" {
		t.Fatalf("%+v", sh)
	}
	name, pub, fp, err := a.MemberKey(ctx, "BOB")
	if err != nil || name != "bob" || fp != b.Fingerprint() {
		t.Fatalf("%q %q %v (want %q)", name, fp, err, b.Fingerprint())
	}
	if err := a.AddMember(ctx, sh.ID, name, pub); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := a.MemberKey(ctx, "nobody"); err == nil {
		t.Fatal("unknown user")
	}

	// Alice moves a site and its login into the share; the context goes along since nothing else uses it.
	site, _ := a.PutOne(ctx, "", vault.Item{Kind: vault.KindContext, Name: "Netflix", ContextType: vault.ContextWebsite,
		URLs: []string{"https://netflix.com"}})
	login, _ := a.PutOne(ctx, "", vault.Item{Kind: vault.KindSecret, Type: vault.TypePassword, Name: "Netflix login",
		Contexts: []string{site}, Fields: map[string]string{"username": "fam", "password": "pw1"}})
	// A second context shared by a staying secret: the moved secret gets a copy.
	mail, _ := a.PutOne(ctx, "", vault.Item{Kind: vault.KindContext, Name: "Mail", ContextType: vault.ContextOther})
	wifi, _ := a.PutOne(ctx, "", vault.Item{Kind: vault.KindSecret, Type: vault.TypePassword, Name: "Wifi",
		Contexts: []string{mail}, Fields: map[string]string{"password": "w"}})
	mine, _ := a.PutOne(ctx, "", vault.Item{Kind: vault.KindSecret, Type: vault.TypePassword, Name: "Mail login",
		Contexts: []string{mail}, Fields: map[string]string{"password": "m"}})
	if err := a.Move(ctx, []string{login, wifi}, sh.ID); err != nil {
		t.Fatal(err)
	}
	if a.ItemShare[login] != sh.ID || a.ItemShare[site] != sh.ID || a.ItemShare[wifi] != sh.ID {
		t.Fatalf("not moved: %v", a.ItemShare)
	}
	if a.ItemShare[mail] != "" || a.ItemShare[mine] != "" {
		t.Fatal("a context still used at home stays at home")
	}
	copyID := a.Items[wifi].Contexts[0]
	if copyID == mail || a.ItemShare[copyID] != sh.ID || a.Items[copyID].Name != "Mail" {
		t.Fatalf("the moved secret should link a copy of Mail in the share: %v", a.Items[wifi].Contexts)
	}
	if _, ok := stA.Items[login]; ok {
		t.Fatal("moved items leave the personal vault")
	}
	if del, _, err := a.Trash(ctx); err != nil || len(del) != 0 {
		t.Fatalf("a move isn't a delete: %v %v", del, err)
	}

	// Bob sees and edits the shared items; Alice gets his change.
	if err := b.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if b.Items[login].Fields["password"] != "pw1" || b.ItemShare[login] != sh.ID || len(b.ShareList()) != 1 {
		t.Fatalf("bob: %+v %v", b.Items[login], b.ItemShare)
	}
	upd := b.Items[login]
	upd.Fields = map[string]string{"username": "fam", "password": "pw2"}
	if _, err := b.PutOne(ctx, login, upd); err != nil {
		t.Fatal(err)
	}
	if err := a.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if a.Items[login].Fields["password"] != "pw2" || len(a.Items[login].History) != 1 {
		t.Fatalf("alice: %+v", a.Items[login])
	}
	// Bob can't manage the share or touch a share he isn't in.
	if err := b.RenameShare(ctx, sh.ID, "Mine now"); err == nil {
		t.Fatal("only the owner renames")
	}
	if err := b.RemoveMember(ctx, sh.ID, "alice"); err == nil {
		t.Fatal("only the owner removes others")
	}
	if code, _ := raw(t, http.MethodGet, e.url+"/api/v2/shares/"+sh.ID+"/sync?since=0", c.State().Token, nil); code != http.StatusNotFound {
		t.Fatalf("carol isn't a member: %d", code)
	}
	if code, _ := raw(t, http.MethodPost, e.url+"/api/v2/shares/"+sh.ID+"/items", c.State().Token,
		map[string]any{"writes": []map[string]any{{"id": login, "delete": true}}}); code != http.StatusNotFound {
		t.Fatalf("carol can't write: %d", code)
	}

	// Rename shows up for Bob; a fresh login on another device sees the share too.
	if err := a.RenameShare(ctx, sh.ID, "Family 2"); err != nil {
		t.Fatal(err)
	}
	_, b2, err := client.Login(ctx, e.url, "bob", "Battery-Staple-7", "b2")
	if err != nil {
		t.Fatal(err)
	}
	if s, err := b2.FindShare("family 2"); err != nil || b2.Items[login].Fields["password"] != "pw2" {
		t.Fatalf("%+v %v", s, err)
	}

	// Bob moves the login home: it leaves the share for everyone.
	if err := b.Move(ctx, []string{login}, ""); err != nil {
		t.Fatal(err)
	}
	if b.ItemShare[login] != "" || stB.Items[login].Data == "" || b.ItemShare[site] != "" {
		t.Fatal("moved home, with its context")
	}
	a.Refresh(ctx)
	if _, ok := a.Items[login]; ok {
		t.Fatal("alice no longer sees it")
	}

	// Removing Bob drops the share from his vault; his own copy stays.
	if err := a.RemoveMember(ctx, sh.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	if err := b.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if len(b.ShareList()) != 0 || b.ItemShare[wifi] != "" {
		t.Fatalf("bob still has %v", b.ShareList())
	}
	if _, ok := b.Items[wifi]; ok {
		t.Fatal("shared items go with the share")
	}
	if _, ok := b.Items[login]; !ok {
		t.Fatal("the item he moved home is his")
	}

	// Deleting the share deletes its items.
	if err := a.DeleteShare(ctx, sh.ID); err != nil {
		t.Fatal(err)
	}
	a.Refresh(ctx)
	if _, ok := a.Items[wifi]; ok || len(a.ShareList()) != 0 {
		t.Fatal("share deleted")
	}
	// Changing the master password keeps sharing working (the private key is sealed with the vault key).
	if err := a.ChangePassword(ctx, "Brand-New-Pass-99"); err != nil {
		t.Fatal(err)
	}
	_, a2, err := client.Login(ctx, e.url, "alice", "Brand-New-Pass-99", "a2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a2.CreateShare(ctx, "After"); err != nil {
		t.Fatal(err)
	}
}
