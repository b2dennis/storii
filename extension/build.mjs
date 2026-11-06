// Builds dist/chrome and dist/firefox from src/. No bundler: the sources are plain ES modules.
import { cpSync, mkdirSync, rmSync, writeFileSync, readFileSync } from 'node:fs';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url)));
const version = pkg.version || '2.0.0';

const base = {
  manifest_version: 3,
  name: 'storii',
  version,
  description: 'Zero-knowledge passwords, 2FA codes and API keys, filled into websites.',
  icons: { 16: 'icons/icon-16.png', 32: 'icons/icon-32.png', 48: 'icons/icon-48.png', 128: 'icons/icon-128.png' },
  permissions: ['storage', 'alarms', 'activeTab', 'clipboardWrite', 'clipboardRead'],
  host_permissions: ['<all_urls>'],
  action: { default_popup: 'popup/popup.html', default_title: 'storii', default_icon: { 16: 'icons/icon-16.png', 32: 'icons/icon-32.png' } },
  content_scripts: [{ matches: ['<all_urls>'], js: ['content.js'], all_frames: true, run_at: 'document_idle' }],
  commands: {
    'fill-login': { suggested_key: { default: 'Ctrl+Shift+L', mac: 'Command+Shift+L' }, description: 'Fill the login or 2FA code for this page' },
    _execute_action: { suggested_key: { default: 'Ctrl+Shift+K', mac: 'Command+Shift+K' } },
  },
  // Argon2 runs as WebAssembly.
  content_security_policy: { extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'" },
};

const targets = {
  chrome: { ...base, background: { service_worker: 'background.js', type: 'module' }, minimum_chrome_version: '116' },
  firefox: {
    ...base,
    background: { scripts: ['background.js'], type: 'module' },
    browser_specific_settings: { gecko: { id: 'storii@base2.sh', strict_min_version: '128.0' } },
  },
};

for (const [name, manifest] of Object.entries(targets)) {
  const out = new URL(`./dist/${name}/`, import.meta.url);
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  cpSync(new URL('./src/', import.meta.url), out, { recursive: true });
  writeFileSync(new URL('manifest.json', out), JSON.stringify(manifest, null, 2) + '\n');
  console.log(`built dist/${name}`);
}
