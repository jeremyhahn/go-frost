# Dockerfile for FROST distributed transport tests
# This container runs integration tests that verify FROST works correctly
# in a real distributed environment with actual HTTP network communication.

FROM golang:1.25.4-alpine AS builder

# Install build dependencies including gcc for CGO (required for race detector)
RUN apk add --no-cache git make gcc musl-dev

# Set working directory
WORKDIR /build

# Copy go module files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build test binary (optional, for faster test execution)
RUN CGO_ENABLED=1 go test -c -tags=integration -race -o /transport-test ./test/transport/

# Final stage
FROM golang:1.25.4-alpine

# Install runtime dependencies including gcc for race detector
RUN apk add --no-cache ca-certificates gcc musl-dev

# Set working directory
WORKDIR /app

# Copy source from builder
COPY --from=builder /build /app

# Run transport tests with CGO enabled
ENV CGO_ENABLED=1
CMD ["go", "test", "-v", "-race", "-timeout", "300s", "-tags=integration", "./test/transport/"]
