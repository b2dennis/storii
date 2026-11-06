BUILD_DIR := "./build/bin"
EXE := if os() == "windows" { ".exe" } else { "" }

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
winres version="2.0.0":
  python3 assets/make_icons.py cmd/storii-tray/icons 16 20 24 32 40 48 64 256
  python3 assets/make_winres.py {{version}}

test-extension:
  cd extension && npm ci && npm test

test-android:
  cd android && ./gradlew testDebugUnitTest

test-ios:
  cd ios/StoriiCore && swift test

# End to end against `just dev` running: the extension in Chromium (with CLI interop) and the iOS core round trip
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

image:
  docker build -t ghcr.io/b2dennis/storii-api:latest .

clean:
  rm -rf {{BUILD_DIR}} extension/dist
