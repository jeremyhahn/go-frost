# Dockerfile for FROST integration tests
# This container runs comprehensive end-to-end integration tests
# in an isolated environment separate from the host OS.

FROM golang:1.25-alpine

# Install test dependencies
RUN apk add --no-cache \
    git \
    make \
    gcc \
    musl-dev \
    bash

# Set working directory
WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download

# Copy all source code
COPY . .

# Set environment for testing
ENV CGO_ENABLED=1
ENV GOOS=linux
ENV GOARCH=amd64

# Default command runs integration tests
CMD ["make", "integration-test-internal"]
