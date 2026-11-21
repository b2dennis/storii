// Password history, as internal/vault/history.go (shared cases: testdata/history.json).
export const MAX_HISTORY = 10;
export const HISTORY_FIELDS = ['password', 'key'];

// next as it should be stored when it replaces prev; now is an ISO time without fractions. The history always comes
// from prev: each history field whose value changed adds prev's value in front.
export function withHistory(prev, next, now) {
  const h = [...(prev?.history || [])];
  if (prev?.kind === 'secret') {
    for (const f of [...HISTORY_FIELDS].reverse()) {
      const old = prev.fields?.[f];
      if (old && old !== next.fields?.[f]) h.unshift({ field: f, value: old, changed_at: now });
    }
  }
  const out = { ...next };
  if (h.length) out.history = h.slice(0, MAX_HISTORY);
  else delete out.history;
  return out;
}
