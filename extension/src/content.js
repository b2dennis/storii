// storii content script: finds login and one-time-code fields, offers the matching secrets in a small picker when
// one is focused, fills them, and notices submitted logins so they can be saved. It never sees secrets of other
// sites: the background only answers for this frame's own host.
(() => {
  if (window.__storii) return;
  window.__storii = true;

  const send = (msg) =>
    new Promise((resolve, reject) =>
      chrome.runtime.sendMessage(msg, (r) => {
        if (chrome.runtime.lastError) return reject(new Error(chrome.runtime.lastError.message));
        if (!r) return reject(new Error('no answer'));
        r.error ? reject(new Error(r.error)) : resolve(r.result);
      }));

  // Field detection.

  const OTP_RE = /one[-_ ]?time|otp|totp|2fa|mfa|two[-_ ]?factor|verification[-_ ]?code|auth(entication)?[-_ ]?code|security[-_ ]?code|passcode|token/i;
  const USER_RE = /user|login|email|e-mail|account|identifier|phone/i;

  function visible(el) {
    if (el.disabled || el.readOnly) return false;
    const r = el.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) return false;
    const st = getComputedStyle(el);
    return st.visibility !== 'hidden' && st.display !== 'none' && st.opacity !== '0';
  }

  const textual = (el) => el instanceof HTMLInputElement &&
    ['text', 'email', 'tel', 'number', ''].includes((el.getAttribute('type') || '').toLowerCase());

  function describe(el) {
    return [el.name, el.id, el.getAttribute('autocomplete'), el.getAttribute('aria-label'), el.placeholder,
      el.labels?.[0]?.textContent].filter(Boolean).join(' ');
  }

  function isOtpField(el) {
    if (!textual(el) && el.type !== 'password') return false;
    const ac = (el.getAttribute('autocomplete') || '').toLowerCase();
    if (ac.includes('one-time-code')) return true;
    if (el.type === 'password' && !OTP_RE.test(describe(el))) return false;
    const max = Number(el.getAttribute('maxlength') || 0);
    if (OTP_RE.test(describe(el)) && !/password/i.test(describe(el))) return true;
    return el.inputMode === 'numeric' && max >= 6 && max <= 8;
  }

  // Split code inputs: several neighbouring one-character boxes.
  function otpGroup(el) {
    if (Number(el.getAttribute('maxlength')) !== 1) return null;
    const box = el.parentElement?.parentElement || el.parentElement;
    const group = [...(box?.querySelectorAll('input') || [])].filter((i) => Number(i.getAttribute('maxlength')) === 1 && visible(i));
    return group.length >= 4 && group.length <= 10 ? group : null;
  }

  function usernameFor(pw) {
    const scope = pw.form || document;
    const inputs = [...scope.querySelectorAll('input')].filter((i) => visible(i) && (textual(i)));
    const before = inputs.filter((i) => i.compareDocumentPosition(pw) & Node.DOCUMENT_POSITION_FOLLOWING);
    const tagged = inputs.find((i) => /username|email/.test(i.getAttribute('autocomplete') || ''));
    if (tagged) return tagged;
    return before.reverse().find((i) => USER_RE.test(describe(i)) || i.type === 'email') || before[0] || null;
  }

  function passwordFields(scope = document) {
    return [...scope.querySelectorAll('input[type=password]')].filter((i) => visible(i) && !isOtpField(i));
  }

  // What kind of field is el, for the picker?
  function role(el) {
    if (!(el instanceof HTMLInputElement) || !visible(el)) return null;
    if (isOtpField(el) || otpGroup(el)) return 'otp';
    if (el.type === 'password') return 'password';
    if (textual(el)) {
      const scope = el.form || document;
      const pw = passwordFields(scope).find((p) => usernameFor(p) === el);
      if (pw) return 'username';
      // A username-only first step ("Next" before the password page).
      if (/username|email/.test(el.getAttribute('autocomplete') || '') || (el.form && USER_RE.test(describe(el)) &&
        [...el.form.querySelectorAll('input')].filter((i) => textual(i) && visible(i)).length === 1)) return 'username';
    }
    return null;
  }

  // Filling, in a way frameworks (React, Vue, Angular) notice.

  function setValue(el, value) {
    el.focus();
    const proto = Object.getPrototypeOf(el);
    const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
    setter ? setter.call(el, value) : (el.value = value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  }

  function fillLogin(anchor, { username, password }) {
    let pw = anchor?.type === 'password' ? anchor : null;
    const scope = anchor?.form || document;
    pw ||= passwordFields(scope)[0] || passwordFields()[0] || null;
    const user = pw ? usernameFor(pw) : (anchor && role(anchor) === 'username' ? anchor : null);
    if (user && username) setValue(user, username);
    if (pw && password) setValue(pw, password);
    (pw || user)?.focus();
    return !!(pw || user);
  }

  function fillCode(anchor, code) {
    const target = anchor && role(anchor) === 'otp' ? anchor :
      [...document.querySelectorAll('input')].find((i) => visible(i) && (isOtpField(i) || otpGroup(i)));
    if (!target) return false;
    const group = otpGroup(target);
    if (group) {
      group.forEach((box, i) => setValue(box, code[i] || ''));
    } else {
      setValue(target, code);
    }
    return true;
  }

  // The picker, in a closed shadow root so the page can neither style nor read it.

  let host = null, shadow = null, anchorEl = null, typedAt = 0;

  function closePicker() {
    host?.remove();
    host = shadow = anchorEl = null;
  }

  function picker(anchor, rows) {
    closePicker();
    anchorEl = anchor;
    host = document.createElement('storii-picker');
    shadow = host.attachShadow({ mode: 'closed' });
    const r = anchor.getBoundingClientRect();
    shadow.innerHTML = `<style>
      :host { all: initial; }
      .box { position: fixed; z-index: 2147483647; min-width: 240px; max-width: 360px; background: #fff; color: #1d1d1f;
        border: 1px solid #d0d0d7; border-radius: 10px; box-shadow: 0 8px 24px rgba(0,0,0,.18); padding: 4px;
        font: 13px/1.35 system-ui, -apple-system, "Segoe UI", sans-serif; }
      @media (prefers-color-scheme: dark) { .box { background: #26262b; color: #f2f2f5; border-color: #3d3d45; } }
      button { all: unset; display: flex; gap: 10px; align-items: center; width: 100%; box-sizing: border-box;
        padding: 7px 10px; border-radius: 7px; cursor: pointer; }
      button:hover, button:focus-visible { background: rgba(88, 86, 214, .14); }
      .t { font-weight: 600; } .s { opacity: .7; font-size: 12px; }
      .ico { width: 22px; height: 22px; border-radius: 6px; background: #5856d6; color: #fff; display: grid; place-items: center;
        font-size: 12px; font-weight: 700; flex: none; }
    </style><div class="box" role="listbox"></div>`;
    const box = shadow.querySelector('.box');
    box.style.left = `${Math.max(4, Math.min(r.left, innerWidth - 250))}px`;
    box.style.top = r.bottom + 230 > innerHeight && r.top > 230 ? `${r.top - 4}px` : `${r.bottom + 4}px`;
    if (r.bottom + 230 > innerHeight && r.top > 230) box.style.transform = 'translateY(-100%)';
    for (const row of rows) {
      const b = document.createElement('button');
      b.setAttribute('role', 'option');
      const ico = document.createElement('span');
      ico.className = 'ico';
      ico.textContent = row.icon;
      const text = document.createElement('span');
      const t = document.createElement('div');
      t.className = 't';
      t.textContent = row.title;
      text.append(t);
      if (row.sub) {
        const s = document.createElement('div');
        s.className = 's';
        s.textContent = row.sub;
        text.append(s);
      }
      b.append(ico, text);
      b.addEventListener('mousedown', (e) => e.preventDefault()); // keep focus in the field
      b.addEventListener('click', (e) => {
        e.stopPropagation();
        row.action();
      });
      box.append(b);
    }
    document.documentElement.append(host);
  }

  async function choose(anchor, id) {
    closePicker();
    try {
      const cred = await send({ type: 'credential', id });
      if (cred.code) fillCode(anchor, cred.code);
      else fillLogin(anchor, cred);
    } catch (e) {
      console.warn('storii:', e.message);
    }
  }

  async function offer(anchor) {
    const kind = role(anchor);
    if (!kind) return;
    let res;
    const asked = performance.now();
    try {
      res = await send({ type: 'matches' });
    } catch {
      return; // extension reloaded
    }
    // Don't pop up after the user moved on or started typing while we waited.
    if (document.activeElement !== anchor || typedAt > asked) return;
    if (res.locked) {
      picker(anchor, [{ icon: '🔒', title: 'Unlock storii', sub: 'to fill this form', action: () => { closePicker(); send({ type: 'openUnlock' }); } }]);
      return;
    }
    const want = kind === 'otp' ? 'totp' : 'password';
    const rows = res.items.filter((i) => i.type === want).map((i) => ({
      icon: want === 'totp' ? '2F' : (i.name[0] || '?').toUpperCase(),
      title: i.name,
      sub: want === 'totp' ? (i.username ? `2FA code · ${i.username}` : '2FA code') : i.username,
      action: () => choose(anchor, i.id),
    }));
    if (rows.length) picker(anchor, rows);
  }

  document.addEventListener('focusin', (e) => {
    const el = e.composedPath?.()[0] || e.target;
    if (el === anchorEl) return;
    closePicker();
    if (el instanceof HTMLInputElement) offer(el);
  }, true);
  document.addEventListener('click', (e) => {
    const el = e.composedPath?.()[0] || e.target;
    if (host && e.target !== host && el !== anchorEl) closePicker();
    else if (!host && el instanceof HTMLInputElement && el === document.activeElement) offer(el);
  }, true);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closePicker();
  }, true);
  // Typing means the user isn't picking: get out of the way (the picker would cover the submit button).
  document.addEventListener('input', (e) => {
    if (!e.isTrusted) return;
    typedAt = performance.now();
    if (e.target === anchorEl) closePicker();
  }, true);
  addEventListener('scroll', closePicker, true);
  addEventListener('resize', closePicker);

  // Remember submitted logins so the background can offer to save them.

  function captureSubmit(scope) {
    const pw = passwordFields(scope).find((p) => p.value);
    if (!pw) return;
    const user = usernameFor(pw);
    send({ type: 'submitted', username: user?.value || '', password: pw.value }).catch(() => {});
  }
  document.addEventListener('submit', (e) => captureSubmit(e.target), true);
  document.addEventListener('click', (e) => {
    const b = e.target.closest?.('button, input[type=submit]');
    if (b && (b.type === 'submit' || /log ?in|sign ?in|continue|next/i.test(b.textContent || b.value || ''))) {
      captureSubmit(b.form || document);
    }
  }, true);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && e.target instanceof HTMLInputElement && e.target.type === 'password') captureSubmit(e.target.form || document);
  }, true);

  // The save bar, shown on the page after a login that isn't in the vault yet.

  async function maybeOfferSave() {
    if (window.top !== window) return;
    let p;
    try {
      p = await send({ type: 'pendingSave' });
    } catch {
      return;
    }
    if (!p) return;
    const bar = document.createElement('storii-save');
    const sh = bar.attachShadow({ mode: 'closed' });
    sh.innerHTML = `<style>
      .bar { position: fixed; top: 12px; right: 12px; z-index: 2147483647; background: #fff; color: #1d1d1f; border-radius: 12px;
        border: 1px solid #d0d0d7; box-shadow: 0 8px 24px rgba(0,0,0,.18); padding: 12px 14px; width: 300px;
        font: 13px/1.4 system-ui, -apple-system, "Segoe UI", sans-serif; }
      @media (prefers-color-scheme: dark) { .bar { background: #26262b; color: #f2f2f5; border-color: #3d3d45; } }
      .row { display: flex; gap: 8px; justify-content: flex-end; margin-top: 10px; }
      button { font: inherit; border: 0; border-radius: 7px; padding: 6px 12px; cursor: pointer; }
      .save { background: #5856d6; color: #fff; } .no { background: transparent; color: inherit; }
    </style><div class="bar" role="dialog"><b></b><div class="s"></div>
    <div class="row"><button class="no">Not now</button><button class="save">Save</button></div></div>`;
    sh.querySelector('b').textContent = p.update ? `Update the password for ${p.host}?` : `Save this login for ${p.host}?`;
    sh.querySelector('.s').textContent = p.username ? `as ${p.username}, in storii` : 'in storii';
    sh.querySelector('.save').onclick = () => send({ type: 'confirmSave', save: true }).finally(() => bar.remove());
    sh.querySelector('.no').onclick = () => send({ type: 'confirmSave', save: false }).finally(() => bar.remove());
    document.documentElement.append(bar);
  }
  if (document.readyState === 'complete') maybeOfferSave();
  else addEventListener('load', maybeOfferSave);

  // Requests from the background: the popup picked something, or the keyboard shortcut.

  chrome.runtime.onMessage.addListener((msg) => {
    const active = document.activeElement instanceof HTMLInputElement ? document.activeElement : null;
    if (msg.type === 'fill') {
      if (msg.code) fillCode(active, msg.code);
      else fillLogin(active, msg);
    }
    if (msg.type === 'fillShortcut') {
      (async () => {
        const { locked, items } = await send({ type: 'matches' });
        if (locked) return;
        const otp = active && role(active) === 'otp';
        const first = items.find((i) => i.type === (otp ? 'totp' : 'password'));
        if (first) choose(active, first.id);
      })().catch(() => {});
    }
  });
})();
