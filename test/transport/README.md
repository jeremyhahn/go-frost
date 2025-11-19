# FROST Distributed Network Transport Tests

This directory contains comprehensive distributed network transport tests for the FROST threshold signature scheme. These tests verify that FROST works correctly in a real distributed environment with actual HTTP network communication between independent participant nodes.

## Overview

The transport tests prove that FROST works in production-like distributed scenarios by:

- **Running multiple independent HTTP servers** - Each participant runs as a separate HTTP server on different ports
- **Using actual network transport** - All communication happens over HTTP (not in-process)
- **Simulating realistic distributed scenarios** - Including node failures, timeouts, and concurrent operations
- **Testing complete end-to-end workflows** - From key generation through signing and verification

## Architecture

### Components

1. **node.go** - HTTP server implementation for FROST participant nodes
   - Exposes REST endpoints: `/round1`, `/round2`, `/verify`, `/health`
   - Each node manages its own key package and signing sessions
   - Stateful session management for multi-round signing protocols

2. **coordinator.go** - Network coordinator for distributed signing
   - Orchestrates distributed signing over HTTP
   - Collects commitments from all participants (Round 1)
   - Distributes commitment list and collects signature shares (Round 2)
   - Aggregates final signature

3. **transport_test.go** - Comprehensive distributed test suite
   - Tests 2-of-3, 3-of-5, and larger threshold scenarios
   - Tests network failures and timeout handling
   - Tests concurrent distributed signatures
   - Tests different participant combinations

## Test Scenarios

### Basic Distributed Signing
- `TestDistributedSigning2of3` - 2-of-3 threshold over network
- `TestDistributedSigning3of5` - 3-of-5 threshold over network

### Concurrent Operations
- `TestMultipleDistributedSessions` - Multiple concurrent signing sessions
- `TestSessionIsolation` - Verifies sessions don't interfere with each other

### Participant Combinations
- `TestDifferentParticipantCombinations` - Tests all possible participant combinations

### Failure Scenarios
- `TestNodeFailureHandling` - Tests behavior when nodes are unavailable
- `TestNetworkTimeout` - Tests timeout handling

### Large Scale
- `TestLargeScaleDistributed` - 5-of-7 threshold with multiple nodes

## Running the Tests

### Using Make (Recommended)

```bash
# Run transport tests in Docker
make test-transport

# Or use the integration test alias
make integration-test-transport
```

### Manual Docker Build and Run

```bash
# Build the Docker image
docker build -t go-frost-transport:latest -f test/transport/Dockerfile .

# Run the tests
docker run --rm go-frost-transport:latest
```

## Requirements

- Docker (for containerized test execution)
- Go 1.25.4 or later
- CGO enabled (for race detector)

## Test Output

All tests run with:
- `-race` flag enabled to detect race conditions
- `-v` flag for verbose output
- 300-second timeout for long-running distributed operations

Example successful output:
```
=== RUN   TestDistributedSigning2of3
--- PASS: TestDistributedSigning2of3 (0.16s)
=== RUN   TestDistributedSigning3of5
--- PASS: TestDistributedSigning3of5 (0.03s)
...
PASS
ok  	github.com/jeremyhahn/go-frost/test/transport	1.461s
```

## Key Features Tested

1. **Actual HTTP servers** - Each participant runs a real HTTP server
2. **Network isolation** - Nodes communicate only via HTTP (no shared memory)
3. **Port management** - Each test uses different port ranges to avoid conflicts
4. **Session management** - Proper handling of concurrent signing sessions
5. **Error handling** - Graceful handling of network failures and timeouts
6. **Verification** - Both signing participants and non-participants can verify signatures

## Network Protocol

### Round 1: Commitment Collection
```
Coordinator -> POST /round1 -> Participant Nodes
            <- Commitments   <-
```

### Round 2: Signature Share Collection
```
Coordinator -> POST /round2 (with commitment list) -> Participant Nodes
            <- Signature Shares                     <-
```

### Verification
```
Coordinator -> POST /verify (with signature) -> Any Node
            <- Valid/Invalid                 <-
```

## Notes

- Tests run in Docker containers for isolation and reproducibility
- Each test uses different port ranges to avoid conflicts
- All tests verify complete end-to-end workflows
- No "known issues" - all assertions pass
- Race detector enabled to ensure thread safety
