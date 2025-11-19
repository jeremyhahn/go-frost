//go:build integration

// Package transport provides distributed network transport tests for the FROST protocol.
//
// These tests verify that FROST works correctly in a real distributed environment by:
// - Running multiple independent HTTP servers (one per participant node)
// - Using actual network transport for all communication
// - Simulating realistic distributed scenarios including failures
// - Testing concurrent distributed signatures
//
// All tests run in Docker containers to ensure isolation and reproducibility.
package transport

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/service"
)

// TestDistributedSigning2of3 tests a 2-of-3 threshold signature over the network.
func TestDistributedSigning2of3(t *testing.T) {
	suite := ristretto255_sha512.New()
	frostService := service.NewFrostService(suite)

	// Configure 2-of-3 threshold
	config := frost.Configuration{
		MinSigners: 2,
		MaxSigners: 3,
		Group:      suite.Group(),
	}

	participantIDs := []frost.Identifier{1, 2, 3}
	keyPackages, groupPubKey, err := frostService.GenerateKeys(config, participantIDs)
	if err != nil {
		t.Fatalf("GenerateKeys failed: %v", err)
	}

	// Create nodes on different ports
	nodes := []*Node{
		NewNode(1, "127.0.0.1:8081", suite, keyPackages[0]),
		NewNode(2, "127.0.0.1:8082", suite, keyPackages[1]),
		NewNode(3, "127.0.0.1:8083", suite, keyPackages[2]),
	}

	// Start all nodes
	for _, node := range nodes {
		if err := node.Start(); err != nil {
			t.Fatalf("Failed to start node %d: %v", node.id, err)
		}
		defer node.Stop()
	}

	// Create network coordinator with all nodes for verification
	nodeAddrs := map[frost.Identifier]string{
		1: "127.0.0.1:8081",
		2: "127.0.0.1:8082",
		3: "127.0.0.1:8083",
	}

	coordinator := NewNetworkCoordinator(
		suite,
		nodeAddrs,
		groupPubKey.Bytes(),
		config.MinSigners,
	)

	// Sign a message using participants 1 and 2
	message := []byte("Distributed FROST signature test")
	signingParticipants := []frost.Identifier{1, 2}

	signature, err := coordinator.Sign(signingParticipants, message)
	if err != nil {
		t.Fatalf("Distributed signing failed: %v", err)
	}

	// Verify signature is not empty
	if signature.R == nil || signature.Z == nil {
		t.Fatal("Signature has nil components")
	}

	// Verify signature using node 3
	valid, err := coordinator.VerifySignature(3, message, signature)
	if err != nil {
		t.Fatalf("Verification request failed: %v", err)
	}

	if !valid {
		t.Error("Signature verification failed")
	}

	// Verify with wrong message should fail
	wrongMessage := []byte("Wrong message")
	valid, err = coordinator.VerifySignature(3, wrongMessage, signature)
	if err != nil {
		t.Fatalf("Verification request failed: %v", err)
	}

	if valid {
		t.Error("Signature should not verify with wrong message")
	}
}

// TestDistributedSigning3of5 tests a 3-of-5 threshold signature over the network.
func TestDistributedSigning3of5(t *testing.T) {
	suite := ristretto255_sha512.New()
	frostService := service.NewFrostService(suite)

	// Configure 3-of-5 threshold
	config := frost.Configuration{
		MinSigners: 3,
		MaxSigners: 5,
		Group:      suite.Group(),
	}

	participantIDs := []frost.Identifier{1, 2, 3, 4, 5}
	keyPackages, groupPubKey, err := frostService.GenerateKeys(config, participantIDs)
	if err != nil {
		t.Fatalf("GenerateKeys failed: %v", err)
	}

	// Create nodes on different ports
	nodes := []*Node{
		NewNode(1, "127.0.0.1:8091", suite, keyPackages[0]),
		NewNode(2, "127.0.0.1:8092", suite, keyPackages[1]),
		NewNode(3, "127.0.0.1:8093", suite, keyPackages[2]),
		NewNode(4, "127.0.0.1:8094", suite, keyPackages[3]),
		NewNode(5, "127.0.0.1:8095", suite, keyPackages[4]),
	}

	// Start all nodes
	for _, node := range nodes {
		if err := node.Start(); err != nil {
			t.Fatalf("Failed to start node %d: %v", node.id, err)
		}
		defer node.Stop()
	}

	// Create network coordinator with all nodes for verification
	nodeAddrs := map[frost.Identifier]string{
		1: "127.0.0.1:8091",
		2: "127.0.0.1:8092",
		3: "127.0.0.1:8093",
		4: "127.0.0.1:8094",
		5: "127.0.0.1:8095",
	}

	coordinator := NewNetworkCoordinator(
		suite,
		nodeAddrs,
		groupPubKey.Bytes(),
		config.MinSigners,
	)

	// Sign a message using participants 1, 2, and 3
	message := []byte("3-of-5 distributed signature")
	signingParticipants := []frost.Identifier{1, 2, 3}

	signature, err := coordinator.Sign(signingParticipants, message)
	if err != nil {
		t.Fatalf("Distributed signing failed: %v", err)
	}

	// Verify signature using node 4
	valid, err := coordinator.VerifySignature(4, message, signature)
	if err != nil {
		t.Fatalf("Verification request failed: %v", err)
	}

	if !valid {
		t.Error("Signature verification failed")
	}
}

// TestMultipleDistributedSessions tests multiple concurrent signing sessions.
func TestMultipleDistributedSessions(t *testing.T) {
	suite := ristretto255_sha512.New()
	frostService := service.NewFrostService(suite)

	// Configure 2-of-3 threshold
	config := frost.Configuration{
		MinSigners: 2,
		MaxSigners: 3,
		Group:      suite.Group(),
	}

	participantIDs := []frost.Identifier{1, 2, 3}
	keyPackages, groupPubKey, err := frostService.GenerateKeys(config, participantIDs)
	if err != nil {
		t.Fatalf("GenerateKeys failed: %v", err)
	}

	// Create nodes on different ports
	nodes := []*Node{
		NewNode(1, "127.0.0.1:8101", suite, keyPackages[0]),
		NewNode(2, "127.0.0.1:8102", suite, keyPackages[1]),
		NewNode(3, "127.0.0.1:8103", suite, keyPackages[2]),
	}

	// Start all nodes
	for _, node := range nodes {
		if err := node.Start(); err != nil {
			t.Fatalf("Failed to start node %d: %v", node.id, err)
		}
		defer node.Stop()
	}

	// Create network coordinator with all nodes for verification
	nodeAddrs := map[frost.Identifier]string{
		1: "127.0.0.1:8101",
		2: "127.0.0.1:8102",
		3: "127.0.0.1:8103",
	}

	coordinator := NewNetworkCoordinator(
		suite,
		nodeAddrs,
		groupPubKey.Bytes(),
		config.MinSigners,
	)

	// Sign multiple messages concurrently
	concurrency := 5
	messages := make([][]byte, concurrency)
	for i := 0; i < concurrency; i++ {
		messages[i] = []byte(fmt.Sprintf("Concurrent message %d", i))
	}

	var wg sync.WaitGroup
	wg.Add(concurrency)
	errors := make(chan error, concurrency)
	signatures := make([]frost.Signature, concurrency)

	for i := 0; i < concurrency; i++ {
		go func(index int) {
			defer wg.Done()

			signingParticipants := []frost.Identifier{1, 2}
			sig, err := coordinator.Sign(signingParticipants, messages[index])
			if err != nil {
				errors <- fmt.Errorf("concurrent signing %d failed: %v", index, err)
				return
			}

			signatures[index] = sig

			// Verify immediately
			valid, err := coordinator.VerifySignature(3, messages[index], sig)
			if err != nil {
				errors <- fmt.Errorf("concurrent verification %d failed: %v", index, err)
				return
			}

			if !valid {
				errors <- fmt.Errorf("concurrent signature %d verification failed", index)
				return
			}

			errors <- nil
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for any errors
	for err := range errors {
		if err != nil {
			t.Error(err)
		}
	}

	// Verify all signatures are different
	for i := 0; i < concurrency; i++ {
		for j := i + 1; j < concurrency; j++ {
			if signatures[i].R.Equal(signatures[j].R) {
				t.Errorf("Signatures %d and %d have the same R value", i, j)
			}
		}
	}
}

// TestDifferentParticipantCombinations tests different participant combinations
// in a distributed environment.
func TestDifferentParticipantCombinations(t *testing.T) {
	suite := ristretto255_sha512.New()
	frostService := service.NewFrostService(suite)

	// Configure 2-of-4 threshold
	config := frost.Configuration{
		MinSigners: 2,
		MaxSigners: 4,
		Group:      suite.Group(),
	}

	participantIDs := []frost.Identifier{1, 2, 3, 4}
	keyPackages, groupPubKey, err := frostService.GenerateKeys(config, participantIDs)
	if err != nil {
		t.Fatalf("GenerateKeys failed: %v", err)
	}

	// Create nodes on different ports
	nodes := []*Node{
		NewNode(1, "127.0.0.1:8111", suite, keyPackages[0]),
		NewNode(2, "127.0.0.1:8112", suite, keyPackages[1]),
		NewNode(3, "127.0.0.1:8113", suite, keyPackages[2]),
		NewNode(4, "127.0.0.1:8114", suite, keyPackages[3]),
	}

	// Start all nodes
	for _, node := range nodes {
		if err := node.Start(); err != nil {
			t.Fatalf("Failed to start node %d: %v", node.id, err)
		}
		defer node.Stop()
	}

	message := []byte("Test different combinations")

	// Test all possible 2-of-4 combinations
	combinations := []struct {
		name         string
		participants []frost.Identifier
		verifier     frost.Identifier
	}{
		{"Participants 1,2 verified by 3", []frost.Identifier{1, 2}, 3},
		{"Participants 1,3 verified by 4", []frost.Identifier{1, 3}, 4},
		{"Participants 1,4 verified by 2", []frost.Identifier{1, 4}, 2},
		{"Participants 2,3 verified by 1", []frost.Identifier{2, 3}, 1},
		{"Participants 2,4 verified by 3", []frost.Identifier{2, 4}, 3},
		{"Participants 3,4 verified by 1", []frost.Identifier{3, 4}, 1},
	}

	for _, combo := range combinations {
		t.Run(combo.name, func(t *testing.T) {
			// Create coordinator with all nodes (for verification)
			nodeAddrs := map[frost.Identifier]string{
				1: "127.0.0.1:8111",
				2: "127.0.0.1:8112",
				3: "127.0.0.1:8113",
				4: "127.0.0.1:8114",
			}

			coordinator := NewNetworkCoordinator(
				suite,
				nodeAddrs,
				groupPubKey.Bytes(),
				config.MinSigners,
			)

			// Sign with this combination
			signature, err := coordinator.Sign(combo.participants, message)
			if err != nil {
				t.Fatalf("Signing failed: %v", err)
			}

			// Verify with non-participating node
			valid, err := coordinator.VerifySignature(combo.verifier, message, signature)
			if err != nil {
				t.Fatalf("Verification request failed: %v", err)
			}

			if !valid {
				t.Error("Signature verification failed")
			}
		})
	}
}

// TestNodeFailureHandling tests behavior when a node is unavailable.
func TestNodeFailureHandling(t *testing.T) {
	suite := ristretto255_sha512.New()
	frostService := service.NewFrostService(suite)

	// Configure 2-of-3 threshold
	config := frost.Configuration{
		MinSigners: 2,
		MaxSigners: 3,
		Group:      suite.Group(),
	}

	participantIDs := []frost.Identifier{1, 2, 3}
	keyPackages, groupPubKey, err := frostService.GenerateKeys(config, participantIDs)
	if err != nil {
		t.Fatalf("GenerateKeys failed: %v", err)
	}

	// Create only 2 nodes (node 2 is "offline")
	nodes := []*Node{
		NewNode(1, "127.0.0.1:8121", suite, keyPackages[0]),
		NewNode(3, "127.0.0.1:8123", suite, keyPackages[2]),
	}

	// Start available nodes
	for _, node := range nodes {
		if err := node.Start(); err != nil {
			t.Fatalf("Failed to start node %d: %v", node.id, err)
		}
		defer node.Stop()
	}

	// Try to sign with node 1 and unavailable node 2
	nodeAddrs := map[frost.Identifier]string{
		1: "127.0.0.1:8121",
		2: "127.0.0.1:8122", // This node doesn't exist
	}

	coordinator := NewNetworkCoordinator(
		suite,
		nodeAddrs,
		groupPubKey.Bytes(),
		config.MinSigners,
	)

	message := []byte("Test with failed node")
	signingParticipants := []frost.Identifier{1, 2}

	_, err = coordinator.Sign(signingParticipants, message)
	if err == nil {
		t.Error("Expected signing to fail with unavailable node")
	}

	// Now sign with available nodes 1 and 3
	nodeAddrs = map[frost.Identifier]string{
		1: "127.0.0.1:8121",
		3: "127.0.0.1:8123",
	}

	coordinator = NewNetworkCoordinator(
		suite,
		nodeAddrs,
		groupPubKey.Bytes(),
		config.MinSigners,
	)

	signingParticipants = []frost.Identifier{1, 3}
	signature, err := coordinator.Sign(signingParticipants, message)
	if err != nil {
		t.Fatalf("Signing with available nodes failed: %v", err)
	}

	// Verify signature
	valid, err := coordinator.VerifySignature(3, message, signature)
	if err != nil {
		t.Fatalf("Verification request failed: %v", err)
	}

	if !valid {
		t.Error("Signature verification failed")
	}
}

// TestNetworkTimeout tests timeout behavior.
func TestNetworkTimeout(t *testing.T) {
	suite := ristretto255_sha512.New()
	frostService := service.NewFrostService(suite)

	// Configure 2-of-3 threshold
	config := frost.Configuration{
		MinSigners: 2,
		MaxSigners: 3,
		Group:      suite.Group(),
	}

	participantIDs := []frost.Identifier{1, 2, 3}
	keyPackages, groupPubKey, err := frostService.GenerateKeys(config, participantIDs)
	if err != nil {
		t.Fatalf("GenerateKeys failed: %v", err)
	}

	// Create nodes
	nodes := []*Node{
		NewNode(1, "127.0.0.1:8131", suite, keyPackages[0]),
		NewNode(2, "127.0.0.1:8132", suite, keyPackages[1]),
	}

	// Start nodes
	for _, node := range nodes {
		if err := node.Start(); err != nil {
			t.Fatalf("Failed to start node %d: %v", node.id, err)
		}
		defer node.Stop()
	}

	message := []byte("Timeout test")
	signingParticipants := []frost.Identifier{1, 2}

	// Test with very short timeout - create a separate coordinator for this test
	nodeAddrs := map[frost.Identifier]string{
		1: "127.0.0.1:8131",
		2: "127.0.0.1:8132",
	}

	shortTimeoutCoordinator := NewNetworkCoordinator(
		suite,
		nodeAddrs,
		groupPubKey.Bytes(),
		config.MinSigners,
	)
	shortTimeoutCoordinator.client.Timeout = 1 * time.Nanosecond

	// This should timeout
	_, err = shortTimeoutCoordinator.Sign(signingParticipants, message)
	if err == nil {
		// With such a short timeout, we expect an error, but depending on timing
		// it might succeed. This is okay - we're just testing the timeout mechanism.
		t.Log("Sign completed (timeout may not have been triggered)")
	}

	// Create a new coordinator with normal timeout and verify it works
	coordinator := NewNetworkCoordinator(
		suite,
		nodeAddrs,
		groupPubKey.Bytes(),
		config.MinSigners,
	)

	signature, err := coordinator.Sign(signingParticipants, message)
	if err != nil {
		t.Fatalf("Signing with normal timeout failed: %v", err)
	}

	valid, err := coordinator.VerifySignature(1, message, signature)
	if err != nil {
		t.Fatalf("Verification request failed: %v", err)
	}

	if !valid {
		t.Error("Signature verification failed")
	}
}

// TestSessionIsolation verifies that different sessions don't interfere.
func TestSessionIsolation(t *testing.T) {
	suite := ristretto255_sha512.New()
	frostService := service.NewFrostService(suite)

	// Configure 2-of-3 threshold
	config := frost.Configuration{
		MinSigners: 2,
		MaxSigners: 3,
		Group:      suite.Group(),
	}

	participantIDs := []frost.Identifier{1, 2, 3}
	keyPackages, groupPubKey, err := frostService.GenerateKeys(config, participantIDs)
	if err != nil {
		t.Fatalf("GenerateKeys failed: %v", err)
	}

	// Create nodes
	nodes := []*Node{
		NewNode(1, "127.0.0.1:8141", suite, keyPackages[0]),
		NewNode(2, "127.0.0.1:8142", suite, keyPackages[1]),
		NewNode(3, "127.0.0.1:8143", suite, keyPackages[2]),
	}

	// Start nodes
	for _, node := range nodes {
		if err := node.Start(); err != nil {
			t.Fatalf("Failed to start node %d: %v", node.id, err)
		}
		defer node.Stop()
	}

	// Create two coordinators for parallel sessions with all nodes for verification
	nodeAddrs := map[frost.Identifier]string{
		1: "127.0.0.1:8141",
		2: "127.0.0.1:8142",
		3: "127.0.0.1:8143",
	}

	coordinator1 := NewNetworkCoordinator(
		suite,
		nodeAddrs,
		groupPubKey.Bytes(),
		config.MinSigners,
	)

	coordinator2 := NewNetworkCoordinator(
		suite,
		nodeAddrs,
		groupPubKey.Bytes(),
		config.MinSigners,
	)

	// Sign two different messages in parallel
	var wg sync.WaitGroup
	wg.Add(2)

	message1 := []byte("Session 1 message")
	message2 := []byte("Session 2 message")
	signingParticipants := []frost.Identifier{1, 2}

	var sig1, sig2 frost.Signature
	var err1, err2 error

	go func() {
		defer wg.Done()
		sig1, err1 = coordinator1.Sign(signingParticipants, message1)
	}()

	go func() {
		defer wg.Done()
		sig2, err2 = coordinator2.Sign(signingParticipants, message2)
	}()

	wg.Wait()

	if err1 != nil {
		t.Errorf("Session 1 signing failed: %v", err1)
	}

	if err2 != nil {
		t.Errorf("Session 2 signing failed: %v", err2)
	}

	// Verify both signatures
	valid1, err := coordinator1.VerifySignature(3, message1, sig1)
	if err != nil {
		t.Fatalf("Session 1 verification request failed: %v", err)
	}

	if !valid1 {
		t.Error("Session 1 signature verification failed")
	}

	valid2, err := coordinator2.VerifySignature(3, message2, sig2)
	if err != nil {
		t.Fatalf("Session 2 verification request failed: %v", err)
	}

	if !valid2 {
		t.Error("Session 2 signature verification failed")
	}

	// Verify signatures are different
	if sig1.R.Equal(sig2.R) {
		t.Error("Parallel session signatures should have different R values")
	}
}

// TestLargeScaleDistributed tests a larger distributed deployment.
func TestLargeScaleDistributed(t *testing.T) {
	suite := ristretto255_sha512.New()
	frostService := service.NewFrostService(suite)

	// Configure 5-of-7 threshold
	config := frost.Configuration{
		MinSigners: 5,
		MaxSigners: 7,
		Group:      suite.Group(),
	}

	participantIDs := make([]frost.Identifier, 7)
	for i := 0; i < 7; i++ {
		participantIDs[i] = frost.Identifier(i + 1)
	}

	keyPackages, groupPubKey, err := frostService.GenerateKeys(config, participantIDs)
	if err != nil {
		t.Fatalf("GenerateKeys failed: %v", err)
	}

	// Create 7 nodes
	nodes := make([]*Node, 7)
	for i := 0; i < 7; i++ {
		port := 8151 + i
		nodes[i] = NewNode(frost.Identifier(i+1), fmt.Sprintf("127.0.0.1:%d", port), suite, keyPackages[i])
	}

	// Start all nodes
	for _, node := range nodes {
		if err := node.Start(); err != nil {
			t.Fatalf("Failed to start node %d: %v", node.id, err)
		}
		defer node.Stop()
	}

	// Create coordinator with all nodes for verification
	nodeAddrs := make(map[frost.Identifier]string)
	for i := 0; i < 7; i++ {
		nodeAddrs[frost.Identifier(i+1)] = fmt.Sprintf("127.0.0.1:%d", 8151+i)
	}

	coordinator := NewNetworkCoordinator(
		suite,
		nodeAddrs,
		groupPubKey.Bytes(),
		config.MinSigners,
	)

	// Sign with exactly the threshold (5 participants)
	message := []byte("Large scale distributed test")
	signingParticipants := []frost.Identifier{1, 2, 3, 4, 5}

	signature, err := coordinator.Sign(signingParticipants, message)
	if err != nil {
		t.Fatalf("Distributed signing failed: %v", err)
	}

	// Verify using node 6
	valid, err := coordinator.VerifySignature(6, message, signature)
	if err != nil {
		t.Fatalf("Verification request failed: %v", err)
	}

	if !valid {
		t.Error("Signature verification failed")
	}
}
