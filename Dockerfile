# Dockerfile for go-frost
# Multi-stage build for minimal production image

# Build stage
FROM --platform=$BUILDPLATFORM golang:1.25.5-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make ca-certificates

# Create non-root user for final image
RUN addgroup -S frost && adduser -S frost -G frost

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build arguments for cross-compilation
ARG TARGETOS
ARG TARGETARCH

# Build static binary for target platform
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w" \
    -o frost \
    ./cmd/frost

# Test stage (runs on build platform)
FROM builder AS tester
RUN CGO_ENABLED=0 go test -v ./pkg/...

# Production stage - minimal scratch image
FROM scratch AS production

# Copy CA certificates from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy passwd/group for non-root user
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

# Copy binary from builder
COPY --from=builder /build/frost /frost

# Use non-root user
USER frost

# Run the application
ENTRYPOINT ["/frost"]
