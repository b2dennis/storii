package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/b2dennis/storii/internal/client"
	"github.com/b2dennis/storii/internal/vault"
)

func cmdShare(ctx context.Context, v *client.Vault, args []string) error {
	fs := newFlags("share")
	yes := fs.Bool("yes", false, "don't ask")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		if fp := v.Fingerprint(); fp != "" {
			fmt.Printf("Your key fingerprint: %s\n", fp)
		}
		shares := v.ShareList()
		if len(shares) == 0 {
			fmt.Println("No shares yet (storii share create NAME).")
			return nil
		}
		counts := map[string]int{}
		for _, sid := range v.ItemShare {
			counts[sid]++
		}
		for _, s := range shares {
			var names []string
			for _, m := range s.Members {
				n := m.Username
				if m.Owner {
					n += " (owner)"
				}
				names = append(names, n)
			}
			fmt.Printf("%s  %s  %d item(s)  members: %s\n", s.ID[:8], s.Name, counts[s.ID], strings.Join(names, ", "))
		}
		return nil
	}
	share := func(q string) (client.Share, error) { return v.FindShare(q) }
	switch pos[0] {
	case "create":
		if err := needArgs(pos[1:], 1, "storii share create NAME"); err != nil {
			return err
		}
		s, err := v.CreateShare(ctx, strings.Join(pos[1:], " "))
		if err != nil {
			return err
		}
		fmt.Printf("Created %s. Add people with `storii share add %q USER`.\n", s.Name, s.Name)
	case "rename":
		if err := needArgs(pos[1:], 2, "storii share rename SHARE NAME"); err != nil {
			return err
		}
		s, err := share(pos[1])
		if err != nil {
			return err
		}
		return v.RenameShare(ctx, s.ID, strings.Join(pos[2:], " "))
	case "add":
		if err := needArgs(pos[1:], 2, "storii share add SHARE USER"); err != nil {
			return err
		}
		s, err := share(pos[1])
		if err != nil {
			return err
		}
		name, pub, fp, err := v.MemberKey(ctx, pos[2])
		if err != nil {
			return err
		}
		fmt.Printf("%s's key fingerprint: %s\n", name, fp)
		if !*yes && !confirm("Ask "+name+" to run `storii share` and compare. Does it match?") {
			return errors.New("not added")
		}
		if err := v.AddMember(ctx, s.ID, name, pub); err != nil {
			return err
		}
		fmt.Printf("Added %s to %s.\n", name, s.Name)
	case "remove":
		if err := needArgs(pos[1:], 2, "storii share remove SHARE USER"); err != nil {
			return err
		}
		s, err := share(pos[1])
		if err != nil {
			return err
		}
		if err := v.RemoveMember(ctx, s.ID, pos[2]); err != nil {
			return err
		}
		fmt.Printf("Removed %s from %s. They keep anything they copied before: change those passwords if that matters.\n", pos[2], s.Name)
	case "move", "unshare":
		target, names := "", pos[1:]
		if pos[0] == "move" {
			if err := needArgs(pos[1:], 2, "storii share move SHARE NAME..."); err != nil {
				return err
			}
			s, err := share(pos[1])
			if err != nil {
				return err
			}
			target, names = s.ID, pos[2:]
		} else if err := needArgs(names, 1, "storii share unshare NAME..."); err != nil {
			return err
		}
		var ids []string
		for _, n := range names {
			e, err := v.Find(vault.KindSecret, n)
			if err != nil {
				return err
			}
			ids = append(ids, e.ID)
		}
		if err := v.Move(ctx, ids, target); err != nil {
			return err
		}
		where := "your vault"
		if target != "" {
			where = v.Shares[target].Name
		}
		fmt.Printf("Moved %d secret(s) to %s.\n", len(ids), where)
	case "delete", "leave":
		if err := needArgs(pos[1:], 1, "storii share delete SHARE"); err != nil {
			return err
		}
		s, err := share(pos[1])
		if err != nil {
			return err
		}
		q := "Leave " + s.Name + "? Its items disappear from your vault."
		if s.Mine {
			q = "Delete " + s.Name + " and its items for every member?"
		}
		if !*yes && !confirm(q) {
			return errors.New("cancelled")
		}
		if err := v.DeleteShare(ctx, s.ID); err != nil {
			return err
		}
		fmt.Println("Done.")
	default:
		return fmt.Errorf("unknown share command %q (try storii help)", pos[0])
	}
	return nil
}
