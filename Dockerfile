# AI Generated
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
# CGO is enabled by default, but we'll be explicit
# Static linking for better portability
RUN go build -a -ldflags '-linkmode external -extldflags "-static"' -o storii-api .

# Runtime stage
FROM alpine:latest AS runtime

# Create non-root user for security
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/storii-api .

# Create data directory and set permissions
RUN mkdir -p /app/data && \
    chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose port (default from your code is 9999)
EXPOSE 9999

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:9999/util/ping || exit 1

# Set default environment variables
ENV ADDRESS=:9999
ENV DBPATH=/app/data/data.db
ENV JWTEXPIRY=24
ENV LOGOUTPUT=stdout

# Run the application
CMD ["./storii-api"]
