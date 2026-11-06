// URL matching, as internal/vault/match.go: same host or a subdomain of the context's host.
export function host(raw) {
  raw = (raw || '').trim();
  if (!raw) return '';
  if (!raw.includes('://')) raw = 'https://' + raw;
  let u;
  try {
    u = new URL(raw);
  } catch {
    return '';
  }
  let h = u.hostname.toLowerCase().replace(/\.$/, '');
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  return h.replace(/^www\./, '');
}

export function matchesHost(contextUrl, pageHost) {
  const ch = host(contextUrl), ph = host(pageHost);
  if (!ch || !ph) return false;
  return ph === ch || ph.endsWith('.' + ch);
}

export function contextMatches(ctx, pageHost) {
  return ctx.kind === 'context' && (ctx.urls || []).some((u) => matchesHost(u, pageHost));
}
