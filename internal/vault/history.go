package vault

import (
	"slices"
	"time"
)

// HistoryEntry is a value a secret had before it was changed: the password or API key, newest first.
type HistoryEntry struct {
	Field     string    `json:"field"`
	Value     string    `json:"value"`
	ChangedAt time.Time `json:"changed_at"`
}

// MaxHistory is how many old values an item keeps.
const MaxHistory = 10

// HistoryFields are the fields whose old values are kept.
var HistoryFields = []string{FieldPassword, FieldKey}

// WithHistory returns next as it should be stored when it replaces prev: each history field whose value changed adds
// prev's value to the history, and the history itself always comes from prev (clients don't edit it). Every client
// does this in its write path, and testdata/history.json holds the cases.
func WithHistory(prev, next Item, now time.Time) Item {
	h := slices.Clone(prev.History)
	if prev.Kind == KindSecret {
		for _, f := range slices.Backward(HistoryFields) {
			if old := prev.Fields[f]; old != "" && old != next.Fields[f] {
				h = slices.Insert(h, 0, HistoryEntry{Field: f, Value: old, ChangedAt: now.UTC().Truncate(time.Second)})
			}
		}
	}
	if len(h) > MaxHistory {
		h = h[:MaxHistory]
	}
	if len(h) == 0 {
		h = nil
	}
	next.History = h
	return next
}
