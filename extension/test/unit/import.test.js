// The CSV importer against testdata/import (shared with internal/importer and the Android app).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseCsv, buildImport, csvRecords, NotAnExport } from '../../src/lib/importcsv.js';

const data = (f) => readFileSync(new URL(`../../../testdata/import/${f}`, import.meta.url), 'utf8');

test('shared cases (Google Password Manager export)', () => {
  const cases = JSON.parse(data('cases.json'));
  const rows = parseCsv(data('google.csv'));
  assert.equal(rows.length, cases.rows.length);
  let n = 0;
  const plan = buildImport(cases.existing, rows, () => `new-${++n}`);
  cases.rows.forEach((want, i) => {
    const got = plan.lines[i];
    const at = `row ${i + 1}`;
    assert.equal(got.action, want.action, at);
    if (want.action === 'username') {
      assert.equal(got.id, want.id, at);
      assert.equal(plan.writes.get(got.id).fields.username, want.username, at);
    }
    if (want.action !== 'add') return;
    const it = plan.writes.get(got.id);
    assert.deepEqual([it.name, it.fields.username, it.fields.password, it.notes || ''],
      [want.name, want.username, want.password, want.notes || ''], at);
    assert.equal(got.differs, !!want.differs, at);
    if (want.context) assert.deepEqual(it.contexts, [want.context], at);
    else if (want.new_context) {
      const c = plan.writes.get(it.contexts[0]);
      for (const [k, v] of Object.entries(want.new_context)) assert.deepEqual(c[k], v, `${at} ${k}`);
    } else assert.equal(it.contexts, undefined, at);
  });
  // Importing the same file again changes nothing.
  const again = buildImport(Object.fromEntries([...Object.entries(cases.existing), ...plan.writes]), rows, () => 'x');
  assert.equal(again.writes.size, 0);
});

test('Zen and Firefox: Export Logins', () => {
  const rows = parseCsv('"url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed","timePasswordChanged"\r\n' +
    '"https://www.example.com","me@example.com","p,w ""1""","","https://www.example.com","{1d}","1700000000000","1700000000000","1700000000000"\r\n');
  assert.deepEqual(rows, [{ name: '', url: 'https://www.example.com', username: 'me@example.com', password: 'p,w "1"', note: '' }]);
  const plan = buildImport({}, rows, (() => { let n = 0; return () => `n${++n}`; })());
  assert.deepEqual(plan.writes.get('n1').urls, ['https://example.com']);
  assert.equal(plan.writes.get('n2').name, 'example.com');
});

test('Safari and Apple Passwords', () => {
  const rows = parseCsv('Title,URL,Username,Password,Notes,OTPAuth\nExample (me),https://example.com/,me,pw,"two\nlines",\n');
  assert.deepEqual(rows, [{ name: 'Example (me)', url: 'https://example.com/', username: 'me', password: 'pw', note: 'two\nlines' }]);
});

test('not an export', () => {
  assert.throws(() => parseCsv('a,b\n1,2\n'), NotAnExport);
  assert.throws(() => parseCsv(''), NotAnExport);
  assert.deepEqual(csvRecords('a,"b\r\nc",d\n\n'), [['a', 'b\nc', 'd']]);
});
