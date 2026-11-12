// Card checks, as internal/vault/card.go (shared cases: testdata/cards.json).
export const cardDigits = (n) => String(n || '').replace(/\D/g, '');

export function cardBrand(number) {
  const d = cardDigits(number);
  const p = (n) => (d.length >= n ? Number(d.slice(0, n)) : -1);
  if (p(2) === 34 || p(2) === 37) return 'amex';
  if ((p(3) >= 300 && p(3) <= 305) || p(2) === 36 || p(2) === 38) return 'diners';
  if (p(4) >= 3528 && p(4) <= 3589) return 'jcb';
  if (p(1) === 4) return 'visa';
  if ((p(2) >= 51 && p(2) <= 55) || (p(4) >= 2221 && p(4) <= 2720)) return 'mastercard';
  if (p(4) === 6011 || p(2) === 65 || (p(3) >= 644 && p(3) <= 649)) return 'discover';
  if (p(2) === 62) return 'unionpay';
  if ([5018, 5020, 5038, 5893, 6304, 6759, 6761, 6762, 6763, 604].includes(p(4))) return 'maestro';
  return '';
}

export function cardValid(number) {
  const d = cardDigits(number);
  if (d.length < 12 || d.length > 19) return false;
  let sum = 0;
  for (let i = 0; i < d.length; i++) {
    let n = Number(d[d.length - 1 - i]);
    if (i % 2 === 1) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
  }
  return sum % 10 === 0;
}

export const cardMasked = (number) => '•••• ' + cardDigits(number).slice(-4);

export function normalizeExpiry(s) {
  s = String(s || '').trim().replace(/ /g, '');
  let m, y;
  if (s.includes('/')) [m, y] = [s.slice(0, s.indexOf('/')), s.slice(s.indexOf('/') + 1)];
  else if (s.length === 4 || s.length === 6) [m, y] = [s.slice(0, 2), s.slice(2)];
  else return '';
  if (y.length === 4) y = y.slice(2);
  if (!/^\d{1,2}$/.test(m) || !/^\d{2}$/.test(y) || +m < 1 || +m > 12) return '';
  return `${m.padStart(2, '0')}/${y}`;
}
