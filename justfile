BUILD_DIR := "./build/bin"
EXE := if os() == "windows" { ".exe" } else { "" }
# The release version; also set in extension/package.json, android/app/build.gradle.kts and ios/project.yml.
VERSION := "2.2.0"

default: build

# Server and CLI binaries in ./build/bin
build:
  go build -o "{{BUILD_DIR}}/storii-api{{EXE}}" ./cmd/storii-api
  go build -o "{{BUILD_DIR}}/storii{{EXE}}" ./cmd/storii

# A throwaway server on :9999 with embedded Postgres and open registration
dev:
  go run ./cmd/storii-devserver

# Go, browser extension, Android and iOS-core unit tests
test: test-go test-extension test-android test-ios

test-go:
  go vet ./...
  go test ./...
  GOOS=windows go build -o /dev/null ./cmd/storii-tray

# Windows tray app (search hotkey, copy to clipboard) for x64 and ARM, plus the Windows CLI
windows:
  GOOS=windows GOARCH=amd64 go build -ldflags "-H windowsgui" -o "{{BUILD_DIR}}/windows-amd64/storii-tray.exe" ./cmd/storii-tray
  GOOS=windows GOARCH=arm64 go build -ldflags "-H windowsgui" -o "{{BUILD_DIR}}/windows-arm64/storii-tray.exe" ./cmd/storii-tray
  GOOS=windows GOARCH=amd64 go build -o "{{BUILD_DIR}}/windows-amd64/storii.exe" ./cmd/storii
  GOOS=windows GOARCH=arm64 go build -o "{{BUILD_DIR}}/windows-arm64/storii.exe" ./cmd/storii

# Regenerates the tray app's icons and Windows resources (icon, manifest, version)
winres version=VERSION:
  python3 assets/make_icons.py cmd/storii-tray/icons 16 20 24 32 40 48 64 256
  python3 assets/make_winres.py {{version}}

test-extension:
  cd extension && npm ci && npm test

test-android:
  cd android && ./gradlew testDebugUnitTest

test-ios:
  cd ios/StoriiCore && swift test

# End to end against `just dev` running: the extension in Chromium (with CLI interop) and Firefox, and the iOS core round trip
e2e: build
  cd extension && STORII_E2E_SERVER=http://localhost:9999 STORII_E2E_CLI=../build/bin/storii{{EXE}} npm run e2e
  cd ios/StoriiCore && STORII_E2E_SERVER=http://localhost:9999 swift test --filter LiveServer

# Unpacked extensions in extension/dist/{chrome,firefox}
extension:
  cd extension && npm ci && npm run build

android:
  cd android && ./gradlew assembleDebug

# Regenerates the vector outputs after changing inputs in testdata/vectors.json
vectors:
  go test ./internal/vault -update

# Server image for linux/amd64 and arm64 with ko (no Docker needed), pushed as :<version> and :2.
# Deliberately not :latest, which v1 installs still pull.
image version=VERSION:
  gh auth token | ko login ghcr.io -u b2dennis --password-stdin
  KO_DOCKER_REPO=ghcr.io/b2dennis/storii-api ko build --bare --platform linux/amd64,linux/arm64 --tags {{version}},2 ./cmd/storii-api

# Release files in build/dist: CLI and server for Linux and macOS, the Windows tray app and CLI, the extensions and
# the Android APK (signed with this machine's debug key, so keep ~/.android/debug.keystore for updates)
dist version=VERSION: windows extension
  #!/usr/bin/env bash
  set -euo pipefail
  rm -rf build/dist && mkdir -p build/dist
  for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
    os=${t%/*}; arch=${t#*/}; d=build/stage/storii-{{version}}-$os-$arch; rm -rf $d; mkdir -p $d
    GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o $d/storii ./cmd/storii
    GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o $d/storii-api ./cmd/storii-api
    cp LICENSE README.md $d/
    tar -C build/stage -czf build/dist/storii-{{version}}-$os-$arch.tar.gz storii-{{version}}-$os-$arch
  done
  for arch in amd64 arm64; do
    d=build/stage/storii-{{version}}-windows-$arch; rm -rf $d; mkdir -p $d
    cp {{BUILD_DIR}}/windows-$arch/storii-tray.exe {{BUILD_DIR}}/windows-$arch/storii.exe LICENSE README.md $d/
    (cd build/stage && zip -qr ../dist/storii-{{version}}-windows-$arch.zip storii-{{version}}-windows-$arch)
  done
  (cd extension/dist/chrome && zip -qr ../../../build/dist/storii-{{version}}-chrome.zip .)
  (cd extension/dist/firefox && zip -qr ../../../build/dist/storii-{{version}}-firefox.zip .)
  (cd android && ./gradlew -q assembleRelease) && cp android/app/build/outputs/apk/release/app-release.apk build/dist/storii-{{version}}.apk
  rm -rf build/stage
  if [ -n "${WEB_EXT_API_KEY:-}" ] || [ -f ~/.config/storii-release/amo.env ]; then just firefox-sign; else echo "No AMO API key: the Firefox extension is only in the unsigned zip"; fi
  cd build/dist && sha256sum * > SHA256SUMS

# Signs the Firefox extension on addons.mozilla.org as an unlisted add-on (signed for self-distribution, not in the
# store) and writes build/dist/storii-<version>-firefox.xpi plus the update manifest that Firefox and Zen poll (see
# update_url in extension/build.mjs). Needs an AMO API key in WEB_EXT_API_KEY and WEB_EXT_API_SECRET, or in
# ~/.config/storii-release/amo.env. A version can only be signed once.
firefox-sign:
  #!/usr/bin/env bash
  set -euo pipefail
  if [ -f ~/.config/storii-release/amo.env ]; then set -a; . ~/.config/storii-release/amo.env; set +a; fi
  v=$(node -p "require('./extension/package.json').version")
  (cd extension && npm ci --silent && npm run build --silent)
  rm -rf build/amo
  (cd extension && npx web-ext sign --channel unlisted --source-dir dist/firefox --artifacts-dir ../build/amo --approval-timeout 900000)
  mkdir -p build/dist
  cp build/amo/*.xpi build/dist/storii-$v-firefox.xpi
  printf '{"addons":{"storii@base2.sh":{"updates":[{"version":"%s","update_link":"https://github.com/b2dennis/storii/releases/download/v%s/storii-%s-firefox.xpi"}]}}}\n' "$v" "$v" "$v" > build/dist/storii-firefox-updates.json
  echo "Signed: build/dist/storii-$v-firefox.xpi"

clean:
  rm -rf {{BUILD_DIR}} extension/dist
