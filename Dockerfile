FROM golang:1.27-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags '-w -s' -o storii-api ./cmd/storii-api

FROM alpine:3.22
RUN apk add --no-cache wget && addgroup -g 1000 -S storii && adduser -u 1000 -S storii -G storii
COPY --from=builder /app/storii-api /usr/local/bin/storii-api
USER storii
EXPOSE 9999
HEALTHCHECK --interval=30s --timeout=5s CMD wget -q -O /dev/null http://localhost:9999/healthz || exit 1
CMD ["storii-api"]
