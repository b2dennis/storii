# Build stage
FROM golang:1.24-alpine AS builder

# Set working directory
WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
# Static binary without CGO
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-w -s' -o storii-api ./cmd/storii-api

# Runtime stage
FROM alpine:latest AS runtime

# Install wget for health check
RUN apk add --no-cache wget

# Create non-root user for security
RUN addgroup -g 1000 -S appgroup && \
    adduser -u 1000 -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/storii-api .

# Create data directory and set permissions
RUN mkdir -p /app/data && \
    chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Run the application
CMD ["./storii-api"]
