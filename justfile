APP_API_NAME := "storii-api"
APP_CLI_NAME := "storii-cli"
API_CMD_DIR := "./cmd/storii-api"
CLI_CMD_DIR := "./cmd/storii-cli"
BUILD_DIR := "./build/bin"
FILE_EXTENSION := if os() == "windows" { ".exe" } else { "" }

default: build

dev: build-api
  @echo "==> Starting dev API server at localhost:9999"
  @DBPATH=":memory:" {{BUILD_DIR}}/{{APP_API_NAME}}{{FILE_EXTENSION}}

build-api:
  @echo "==> Building API server binary"
  @go build -o "{{BUILD_DIR}}/{{APP_API_NAME}}{{FILE_EXTENSION}}" {{API_CMD_DIR}}

build-cli:
  @echo "==> Building CLI client binary"
  @go build -o "{{BUILD_DIR}}/{{APP_CLI_NAME}}{{FILE_EXTENSION}}" {{CLI_CMD_DIR}}

build: build-api build-cli
  @echo "==> ✅ All builds complete!"
  @echo "==> Binaries are in {{BUILD_DIR}}"

clean:
  @echo "==> Cleaning all build artifacts..."
  @rm -rf {{BUILD_DIR}}

test-api *FLAGS="":
  @echo "==> Running API server tests"
  @go test {{API_CMD_DIR}} {{FLAGS}}

test-cli *FLAGS="":
  @echo "==> Running CLI client tests"
  @go test {{CLI_CMD_DIR}} {{FLAGS}}

test *FLAGS="": (test-api FLAGS) (test-cli FLAGS)
  @echo "==> ✅ All tests complete!"

full: (test "-v") build
