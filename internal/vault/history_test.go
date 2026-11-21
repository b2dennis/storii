package vault

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestWithHistory(t *testing.T) {
	b, err := os.ReadFile("../../testdata/history.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Now   time.Time
		Cases []struct {
			Name       string
			Prev, Next Item
			Want       []HistoryEntry
		}
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Cases {
		got := WithHistory(c.Prev, c.Next, v.Now).History
		if !reflect.DeepEqual(got, c.Want) {
			t.Errorf("%s: got %+v, want %+v", c.Name, got, c.Want)
		}
	}
}
