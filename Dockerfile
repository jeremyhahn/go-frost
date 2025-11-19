# Dockerfile for go-frost
# Multi-stage build for minimal production image

# Build stage
FROM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make gcc musl-dev

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN make build

# Test stage
FROM builder AS tester

# Run tests
RUN make test-unit

# Production stage
FROM alpine:latest AS production

# Install CA certificates for HTTPS
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -S frost && adduser -S frost -G frost

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/frost .

# Change ownership
RUN chown -R frost:frost /app

# Switch to non-root user
USER frost

# Run the application
ENTRYPOINT ["/app/frost"]
