package service_test

import (
	"fmt"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/service"
)

// Example demonstrates the basic usage of the FROST service layer.
func Example() {
	// 1. Create a ciphersuite
	suite := ristretto255_sha512.New()

	// 2. Create the FROST service
	frostService := service.NewFrostService(suite)

	// 3. Configure a 2-of-3 threshold scheme
	config := frost.Configuration{
		MinSigners: 2, // Minimum 2 participants required to sign
		MaxSigners: 3, // Total of 3 participants in the group
		Group:      suite.Group(),
	}

	// 4. Generate key shares for participants
	participantIDs := []frost.Identifier{1, 2, 3}
	keyPackages, groupPubKey, err := frostService.GenerateKeys(config, participantIDs)
	if err != nil {
		panic(err)
	}

	// 5. Sign a message with 2 participants (threshold)
	message := []byte("Hello, FROST!")
	signingParticipants := []frost.KeyPackage{keyPackages[0], keyPackages[1]}

	signature, err := frostService.Sign(signingParticipants, message)
	if err != nil {
		panic(err)
	}

	// 6. Verify the signature
	err = frostService.Verify(message, signature, groupPubKey)
	if err != nil {
		fmt.Println("Signature verification failed!")
	} else {
		fmt.Println("Signature verified successfully!")
	}

	// Output: Signature verified successfully!
}

// Example_sessionManager demonstrates asynchronous signing using sessions.
func Example_sessionManager() {
	// 1. Create service and session manager
	suite := ristretto255_sha512.New()
	frostService := service.NewFrostService(suite)
	sessionManager := service.NewSessionManager(frostService)

	// 2. Create a signing session
	participantIDs := []frost.Identifier{1, 2}
	message := []byte("Session-based signing")

	session, err := sessionManager.CreateSession(participantIDs, message)
	if err != nil {
		panic(err)
	}

	// Session has a unique ID
	hasID := session.ID() != ""
	fmt.Printf("Session has ID: %v\n", hasID)

	// 3. Participants add commitments (round one)
	// In a real scenario, each participant would generate and submit their commitment
	commitment1 := frost.SigningCommitments{
		Identifier:             1,
		HidingNonceCommitment:  suite.Group().Generator(),
		BindingNonceCommitment: suite.Group().Generator(),
	}

	err = session.AddCommitment(commitment1)
	if err != nil {
		panic(err)
	}

	// 4. Check session status
	fmt.Printf("Session complete: %v\n", session.IsComplete())

	// 5. List all sessions
	sessions := sessionManager.ListSessions()
	fmt.Printf("Active sessions: %d\n", len(sessions))

	// Output:
	// Session has ID: true
	// Session complete: false
	// Active sessions: 1
}

// Example_differentParticipants demonstrates that any threshold
// combination of participants can create a valid signature.
func Example_differentParticipants() {
	suite := ristretto255_sha512.New()
	frostService := service.NewFrostService(suite)

	// Configure 2-of-3 threshold
	config := frost.Configuration{
		MinSigners: 2,
		MaxSigners: 3,
		Group:      suite.Group(),
	}

	participantIDs := []frost.Identifier{1, 2, 3}
	keyPackages, groupPubKey, _ := frostService.GenerateKeys(config, participantIDs)

	message := []byte("Flexible signing")

	// Different combinations of 2 participants can all sign
	combinations := [][]int{
		{0, 1}, // Participants 1 and 2
		{0, 2}, // Participants 1 and 3
		{1, 2}, // Participants 2 and 3
	}

	for _, combo := range combinations {
		signers := []frost.KeyPackage{keyPackages[combo[0]], keyPackages[combo[1]]}
		signature, _ := frostService.Sign(signers, message)

		err := frostService.Verify(message, signature, groupPubKey)
		if err == nil {
			fmt.Printf("Participants %d and %d: Valid\n",
				combo[0]+1, combo[1]+1)
		}
	}

	// Output:
	// Participants 1 and 2: Valid
	// Participants 1 and 3: Valid
	// Participants 2 and 3: Valid
}
