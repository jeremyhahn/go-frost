// Package main provides the command-line interface for FROST operations.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed25519_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed448_shake256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/p256_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/secp256k1_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/keygen"
	"github.com/jeremyhahn/go-frost/pkg/frost/signing"
	"github.com/jeremyhahn/go-frost/pkg/secmem"
)

var (
	// Version is set at build time via ldflags
	Version = "dev"
	// GitCommit is set at build time via ldflags
	GitCommit = "none"
	// BuildDate is set at build time via ldflags
	BuildDate = "unknown"
)

// getCiphersuite returns the ciphersuite based on the given name.
// Defaults to ristretto255 if name is empty or invalid.
func getCiphersuite(name string) ciphersuite.Ciphersuite {
	switch strings.ToLower(name) {
	case "ed25519", "ed25519-sha512":
		return ed25519_sha512.New()
	case "p256", "p256-sha256":
		return p256_sha256.New()
	case "secp256k1", "secp256k1-sha256":
		return secp256k1_sha256.New()
	case "ed448", "ed448-shake256":
		return ed448_shake256.New()
	case "ristretto255", "ristretto255-sha512", "":
		return ristretto255_sha512.New()
	default:
		fmt.Fprintf(os.Stderr, "Warning: unknown ciphersuite '%s', using ristretto255-sha512\n", name)
		return ristretto255_sha512.New()
	}
}

// getSupportedCiphersuites returns a string listing all supported ciphersuites
func getSupportedCiphersuites() string {
	return `  ristretto255 - FROST(ristretto255, SHA-512) [default, recommended]
  ed25519      - FROST(Ed25519, SHA-512)
  p256         - FROST(P-256, SHA-256) [NIST]
  secp256k1    - FROST(secp256k1, SHA-256) [Bitcoin curve]
  ed448        - FROST(Ed448, SHAKE256) [highest security]`
}

// safeUintToUint32 converts uint to uint32 with bounds check.
// Panics if the value exceeds uint32 max (should be validated before calling).
func safeUintToUint32(v uint) uint32 {
	if v > math.MaxUint32 {
		panic("integer overflow: uint exceeds uint32 max")
	}
	return uint32(v)
}

// safeUintToUint16 converts uint to uint16 with bounds check.
// Panics if the value exceeds uint16 max (should be validated before calling).
func safeUintToUint16(v uint) uint16 {
	if v > math.MaxUint16 {
		panic("integer overflow: uint exceeds uint16 max")
	}
	return uint16(v)
}

// safeUint32ToUint16 converts uint32 to uint16 with bounds check.
// Panics if the value exceeds uint16 max (should be validated before calling).
func safeUint32ToUint16(v uint32) uint16 {
	if v > math.MaxUint16 {
		panic("integer overflow: uint32 exceeds uint16 max")
	}
	return uint16(v)
}

// safeIntToUint16 converts int to uint16 with bounds check.
// Panics if the value is negative or exceeds uint16 max.
func safeIntToUint16(v int) uint16 {
	if v < 0 || v > math.MaxUint16 {
		panic("integer overflow: int out of uint16 range")
	}
	return uint16(v)
}

func main() {
	// Initialize secure memory subsystem (mlock, interrupt handlers)
	secmem.Init()
	defer secmem.Purge()

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "version", "--version", "-v":
		printVersion()
	case "help", "--help", "-h":
		printUsage()
	case "keygen":
		keygenCommand()
	case "sign":
		signCommand()
	case "commit":
		commitCommand()
	case "collect-commitments":
		collectCommitmentsCommand()
	case "sign-share":
		signShareCommand()
	case "collect-shares":
		collectSharesCommand()
	case "aggregate":
		aggregateCommand()
	case "verify":
		verifyCommand()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printVersion() {
	fmt.Printf("%s\n", Version)
}

func printUsage() {
	fmt.Println("FROST Threshold Signature Scheme")
	fmt.Println("RFC 9591 Implementation")
	fmt.Println()
	fmt.Println("Usage: frost <command> [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  keygen       Generate key shares for participants")
	fmt.Println("  sign         Create a threshold signature (local testing)")
	fmt.Println()
	fmt.Println("Distributed Signing:")
	fmt.Println("  commit               Round 1: Generate nonce and commitment")
	fmt.Println("  collect-commitments  Coordinator: Collect all commitments into one file")
	fmt.Println("  sign-share           Round 2: Create signature share")
	fmt.Println("  collect-shares       Coordinator: Collect all shares into one file")
	fmt.Println("  aggregate            Aggregate signature shares into final signature")
	fmt.Println()
	fmt.Println("Verification:")
	fmt.Println("  verify       Verify a threshold signature")
	fmt.Println()
	fmt.Println("Other:")
	fmt.Println("  version      Show version information")
	fmt.Println("  help         Show this help message")
	fmt.Println()
	fmt.Println("Run 'frost <command> --help' for more information on a command.")
}

func keygenCommand() {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	minSigners := fs.Uint("min", 2, "Minimum number of signers (threshold)")
	maxSigners := fs.Uint("max", 3, "Maximum number of signers (total participants)")
	output := fs.String("output", "frost-keys.json", "Output file for key packages")
	ciphersuiteFlag := fs.String("ciphersuite", "ristretto255", "Ciphersuite to use")

	fs.Usage = func() {
		fmt.Println("Usage: frost keygen [options]")
		fmt.Println()
		fmt.Println("Generate FROST key shares for threshold signing")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Supported Ciphersuites:")
		fmt.Println(getSupportedCiphersuites())
		fmt.Println()
		fmt.Println("Example:")
		fmt.Println("  frost keygen --min 2 --max 3 --ciphersuite ristretto255 --output keys.json")
		fmt.Println("  frost keygen --min 2 --max 3 --ciphersuite ed25519 --output keys.json")
	}

	if err := fs.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if *minSigners < 2 {
		fmt.Fprintf(os.Stderr, "Error: min must be at least 2\n")
		os.Exit(1)
	}

	if *minSigners > *maxSigners {
		fmt.Fprintf(os.Stderr, "Error: min cannot exceed max\n")
		os.Exit(1)
	}

	// Validate bounds for uint32/uint16 conversion
	if *maxSigners > math.MaxUint16 {
		fmt.Fprintf(os.Stderr, "Error: max signers exceeds maximum value (%d)\n", math.MaxUint16)
		os.Exit(1)
	}

	// Create ciphersuite
	suite := getCiphersuite(*ciphersuiteFlag)
	grp := suite.Group()

	// Generate participant IDs
	participantIDs := make([]frost.Identifier, *maxSigners)
	for i := uint(0); i < *maxSigners; i++ {
		participantIDs[i] = frost.Identifier(safeUintToUint32(i + 1))
	}

	// Generate secret
	secret, err := grp.RandomScalar()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating secret: %v\n", err)
		os.Exit(1)
	}

	// Generate shares
	dealer := keygen.NewDealer(suite)
	keyPackages, groupPublicKey, err := dealer.GenerateShares(secret, safeUintToUint32(*minSigners), safeUintToUint32(*maxSigners), participantIDs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating shares: %v\n", err)
		os.Exit(1)
	}

	// Prepare output data
	outputData := struct {
		MinSigners     uint32             `json:"min_signers"`
		MaxSigners     uint32             `json:"max_signers"`
		GroupPublicKey string             `json:"group_public_key"`
		KeyPackages    []KeyPackageExport `json:"key_packages"`
	}{
		MinSigners:     safeUintToUint32(*minSigners),
		MaxSigners:     safeUintToUint32(*maxSigners),
		GroupPublicKey: hex.EncodeToString(groupPublicKey.Bytes()),
		KeyPackages:    make([]KeyPackageExport, len(keyPackages)),
	}

	for i, pkg := range keyPackages {
		secretShareBytes := pkg.SecretShare.Bytes()
		outputData.KeyPackages[i] = KeyPackageExport{
			Identifier:  safeUint32ToUint16(uint32(pkg.Identifier)),
			SecretShare: hex.EncodeToString(secretShareBytes),
			PublicKey:   hex.EncodeToString(pkg.GroupPublicKey.Bytes()),
		}
		secmem.ZeroBytes(secretShareBytes)
	}

	// Write to file
	data, err := json.MarshalIndent(outputData, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling output: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*output, data, 0600); err != nil {
		secmem.ZeroBytes(data)
		fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
		os.Exit(1)
	}
	secmem.ZeroBytes(data)

	// Zero the hex-encoded secret share strings in the output struct
	for i := range outputData.KeyPackages {
		secmem.ZeroString(&outputData.KeyPackages[i].SecretShare)
	}

	fmt.Printf("Generated %d key packages (%d-of-%d threshold)\n", *maxSigners, *minSigners, *maxSigners)
	fmt.Printf("Group public key: %s\n", hex.EncodeToString(groupPublicKey.Bytes()))
	fmt.Printf("Key packages saved to: %s\n", *output)
}

type KeyPackageExport struct {
	Identifier  uint16 `json:"identifier"`
	SecretShare string `json:"secret_share"`
	PublicKey   string `json:"public_key"`
}

func signCommand() {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keysFile := fs.String("keys", "frost-keys.json", "Input file containing key packages")
	message := fs.String("message", "", "Message to sign")
	signers := fs.String("signers", "1,2", "Comma-separated list of signer identifiers (e.g., 1,2)")
	output := fs.String("output", "frost-signature.json", "Output file for signature")
	ciphersuiteFlag := fs.String("ciphersuite", "ristretto255", "Ciphersuite to use")

	fs.Usage = func() {
		fmt.Println("Usage: frost sign [options]")
		fmt.Println()
		fmt.Println("Create a threshold signature")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Supported Ciphersuites:")
		fmt.Println(getSupportedCiphersuites())
		fmt.Println()
		fmt.Println("Example:")
		fmt.Println("  frost sign --keys keys.json --message 'Hello World' --signers 1,2 --output sig.json")
		fmt.Println("  frost sign --keys keys.json --message 'Hello World' --ciphersuite ed25519 --signers 1,2")
	}

	if err := fs.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if *message == "" {
		fmt.Fprintf(os.Stderr, "Error: message is required\n")
		fs.Usage()
		os.Exit(1)
	}

	// Read key packages
	keysData, err := os.ReadFile(*keysFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading keys file: %v\n", err)
		os.Exit(1)
	}

	var keysInput struct {
		MinSigners     uint32             `json:"min_signers"`
		MaxSigners     uint32             `json:"max_signers"`
		GroupPublicKey string             `json:"group_public_key"`
		KeyPackages    []KeyPackageExport `json:"key_packages"`
	}

	if err := json.Unmarshal(keysData, &keysInput); err != nil {
		secmem.ZeroBytes(keysData)
		fmt.Fprintf(os.Stderr, "Error parsing keys file: %v\n", err)
		os.Exit(1)
	}
	secmem.ZeroBytes(keysData)

	// Parse signers
	var signerIDs []int
	if _, err := fmt.Sscanf(*signers, "%d,%d", &signerIDs); err != nil {
		// Try parsing as comma-separated list
		var id1, id2 int
		n, _ := fmt.Sscanf(*signers, "%d,%d", &id1, &id2)
		if n >= 2 {
			signerIDs = []int{id1, id2}
		} else {
			fmt.Fprintf(os.Stderr, "Error: invalid signers format, use comma-separated IDs (e.g., 1,2)\n")
			os.Exit(1)
		}
	}

	suite := getCiphersuite(*ciphersuiteFlag)
	grp := suite.Group()

	// Parse group public key
	groupPubKeyBytes, err := hex.DecodeString(keysInput.GroupPublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding group public key: %v\n", err)
		os.Exit(1)
	}
	groupPublicKey, err := grp.DeserializeElement(groupPubKeyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deserializing group public key: %v\n", err)
		os.Exit(1)
	}

	// Get signing key packages
	signingPackages := []frost.KeyPackage{}
	for _, signerID := range signerIDs {
		found := false
		for _, pkg := range keysInput.KeyPackages {
			if pkg.Identifier == safeIntToUint16(signerID) {
				secretBytes, err := hex.DecodeString(pkg.SecretShare)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error decoding secret share: %v\n", err)
					os.Exit(1)
				}
				secret, err := grp.DeserializeScalar(secretBytes)
				secmem.ZeroBytes(secretBytes)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error deserializing secret share: %v\n", err)
					os.Exit(1)
				}

				pubKeyBytes, err := hex.DecodeString(pkg.PublicKey)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error decoding public key: %v\n", err)
					os.Exit(1)
				}
				pubKey, err := grp.DeserializeElement(pubKeyBytes)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error deserializing public key: %v\n", err)
					os.Exit(1)
				}

				signingPackages = append(signingPackages, frost.KeyPackage{
					Identifier:     frost.Identifier(pkg.Identifier),
					SecretShare:    secret,
					GroupPublicKey: pubKey,
				})
				found = true
				break
			}
		}
		if !found {
			fmt.Fprintf(os.Stderr, "Error: signer %d not found in key packages\n", signerID)
			os.Exit(1)
		}
	}

	// Round 1: Generate nonces and commitments
	participants := make([]signing.Participant, len(signingPackages))
	nonces := make([]frost.SigningNonces, len(signingPackages))
	commitments := make(frost.CommitmentList, len(signingPackages))

	for i, pkg := range signingPackages {
		participants[i] = signing.NewParticipant(pkg, suite)
		n, c, err := participants[i].RoundOne()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error in round one: %v\n", err)
			os.Exit(1)
		}
		nonces[i] = n
		commitments[i] = c
	}

	// Round 2: Create signature shares
	messageBytes := []byte(*message)
	signatureShares := make([]frost.SignatureShare, len(signingPackages))
	for i, participant := range participants {
		share, err := participant.RoundTwo(nonces[i], messageBytes, commitments)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error in round two: %v\n", err)
			os.Exit(1)
		}
		signatureShares[i] = share
		nonces[i].Zeroize()
	}

	// Aggregate signature
	aggregator := signing.NewAggregator(suite, keysInput.MinSigners)
	signature, err := aggregator.Aggregate(groupPublicKey, commitments, messageBytes, signatureShares)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error aggregating signature: %v\n", err)
		os.Exit(1)
	}

	// Save signature
	sigOutput := struct {
		Message   string `json:"message"`
		Signature string `json:"signature"`
		PublicKey string `json:"public_key"`
	}{
		Message:   *message,
		Signature: hex.EncodeToString(append(signature.R.Bytes(), signature.Z.Bytes()...)),
		PublicKey: hex.EncodeToString(groupPublicKey.Bytes()),
	}

	sigData, err := json.MarshalIndent(sigOutput, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling signature: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*output, sigData, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing signature file: %v\n", err)
		os.Exit(1)
	}

	// Zero the hex-encoded secret share strings from parsed keys input
	for i := range keysInput.KeyPackages {
		secmem.ZeroString(&keysInput.KeyPackages[i].SecretShare)
	}

	fmt.Printf("Signature created successfully\n")
	fmt.Printf("Message: %s\n", *message)
	fmt.Printf("Signature: %s\n", hex.EncodeToString(append(signature.R.Bytes(), signature.Z.Bytes()...)))
	fmt.Printf("Signature saved to: %s\n", *output)
}

func commitCommand() {
	fs := flag.NewFlagSet("commit", flag.ExitOnError)
	keysFile := fs.String("keys", "frost-keys.json", "Input file containing key packages")
	participantID := fs.Uint("id", 0, "Participant identifier")
	outputCommitment := fs.String("output", "", "Output file for commitment (default: commitment-{id}.json)")
	outputNonces := fs.String("nonces", "", "Output file for private nonces (default: nonces-{id}.json)")
	ciphersuiteFlag := fs.String("ciphersuite", "ristretto255", "Ciphersuite to use")

	fs.Usage = func() {
		fmt.Println("Usage: frost commit [options]")
		fmt.Println()
		fmt.Println("Round 1: Generate nonce and commitment for distributed signing")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Supported Ciphersuites:")
		fmt.Println(getSupportedCiphersuites())
		fmt.Println()
		fmt.Println("Example:")
		fmt.Println("  frost commit --keys keys.json --id 1")
		fmt.Println("  frost commit --keys keys.json --id 1 --ciphersuite ed25519")
	}

	if err := fs.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if *participantID == 0 {
		fmt.Fprintf(os.Stderr, "Error: participant id is required\n")
		fs.Usage()
		os.Exit(1)
	}

	// Set default output filenames if not provided
	if *outputCommitment == "" {
		*outputCommitment = fmt.Sprintf("commitment-%d.json", *participantID)
	}
	if *outputNonces == "" {
		*outputNonces = fmt.Sprintf("nonces-%d.json", *participantID)
	}

	// Read key packages
	keysData, err := os.ReadFile(*keysFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading keys file: %v\n", err)
		os.Exit(1)
	}

	var keysInput struct {
		MinSigners     uint32             `json:"min_signers"`
		MaxSigners     uint32             `json:"max_signers"`
		GroupPublicKey string             `json:"group_public_key"`
		KeyPackages    []KeyPackageExport `json:"key_packages"`
	}

	if err := json.Unmarshal(keysData, &keysInput); err != nil {
		secmem.ZeroBytes(keysData)
		fmt.Fprintf(os.Stderr, "Error parsing keys file: %v\n", err)
		os.Exit(1)
	}
	secmem.ZeroBytes(keysData)

	suite := getCiphersuite(*ciphersuiteFlag)
	grp := suite.Group()

	// Find the participant's key package
	var keyPackage *frost.KeyPackage
	for _, pkg := range keysInput.KeyPackages {
		if pkg.Identifier == safeUintToUint16(*participantID) {
			secretBytes, err := hex.DecodeString(pkg.SecretShare)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error decoding secret share: %v\n", err)
				os.Exit(1)
			}
			secret, err := grp.DeserializeScalar(secretBytes)
			secmem.ZeroBytes(secretBytes)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error deserializing secret share: %v\n", err)
				os.Exit(1)
			}

			pubKeyBytes, err := hex.DecodeString(pkg.PublicKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error decoding public key: %v\n", err)
				os.Exit(1)
			}
			pubKey, err := grp.DeserializeElement(pubKeyBytes)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error deserializing public key: %v\n", err)
				os.Exit(1)
			}

			keyPackage = &frost.KeyPackage{
				Identifier:     frost.Identifier(pkg.Identifier),
				SecretShare:    secret,
				GroupPublicKey: pubKey,
			}
			break
		}
	}

	if keyPackage == nil {
		fmt.Fprintf(os.Stderr, "Error: participant %d not found in key packages\n", *participantID)
		os.Exit(1)
	}

	// Generate nonces and commitment
	participant := signing.NewParticipant(*keyPackage, suite)
	nonces, commitment, err := participant.RoundOne()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating nonces and commitment: %v\n", err)
		os.Exit(1)
	}

	// Save commitment for sharing
	commitmentOutput := struct {
		Identifier        uint16 `json:"identifier"`
		HidingCommitment  string `json:"hiding_commitment"`
		BindingCommitment string `json:"binding_commitment"`
	}{
		Identifier:        safeUint32ToUint16(uint32(commitment.Identifier)),
		HidingCommitment:  hex.EncodeToString(commitment.HidingNonceCommitment.Bytes()),
		BindingCommitment: hex.EncodeToString(commitment.BindingNonceCommitment.Bytes()),
	}

	commitmentData, err := json.MarshalIndent(commitmentOutput, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling commitment: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*outputCommitment, commitmentData, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing commitment file: %v\n", err)
		os.Exit(1)
	}

	// Save private nonces (keep secret!)
	hidingNonceBytes := nonces.HidingNonce.Bytes()
	bindingNonceBytes := nonces.BindingNonce.Bytes()
	noncesOutput := struct {
		Identifier   uint16 `json:"identifier"`
		HidingNonce  string `json:"hiding_nonce"`
		BindingNonce string `json:"binding_nonce"`
	}{
		Identifier:   safeUintToUint16(*participantID),
		HidingNonce:  hex.EncodeToString(hidingNonceBytes),
		BindingNonce: hex.EncodeToString(bindingNonceBytes),
	}
	secmem.ZeroBytes(hidingNonceBytes)
	secmem.ZeroBytes(bindingNonceBytes)

	noncesData, err := json.MarshalIndent(noncesOutput, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling nonces: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*outputNonces, noncesData, 0600); err != nil {
		secmem.ZeroBytes(noncesData)
		fmt.Fprintf(os.Stderr, "Error writing nonces file: %v\n", err)
		os.Exit(1)
	}
	secmem.ZeroBytes(noncesData)

	// Zero the hex-encoded nonce strings in the output struct
	secmem.ZeroString(&noncesOutput.HidingNonce)
	secmem.ZeroString(&noncesOutput.BindingNonce)

	// Zero the hex-encoded secret share strings from parsed keys input
	for i := range keysInput.KeyPackages {
		secmem.ZeroString(&keysInput.KeyPackages[i].SecretShare)
	}

	fmt.Printf("Round 1 completed for participant %d\n", *participantID)
	fmt.Printf("Commitment saved to: %s (share with coordinator)\n", *outputCommitment)
	fmt.Printf("Nonces saved to: %s (keep private!)\n", *outputNonces)
}

func signShareCommand() {
	fs := flag.NewFlagSet("sign-share", flag.ExitOnError)
	keysFile := fs.String("keys", "frost-keys.json", "Input file containing key packages")
	participantID := fs.Uint("id", 0, "Participant identifier")
	noncesFile := fs.String("nonces", "", "Input file containing private nonces (default: nonces-{id}.json)")
	commitmentsFile := fs.String("commitments", "commitments.json", "Input file containing all commitments")
	message := fs.String("message", "", "Message to sign")
	output := fs.String("output", "", "Output file for signature share (default: share-{id}.json)")
	ciphersuiteFlag := fs.String("ciphersuite", "ristretto255", "Ciphersuite to use")

	fs.Usage = func() {
		fmt.Println("Usage: frost sign-share [options]")
		fmt.Println()
		fmt.Println("Round 2: Create signature share for distributed signing")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Supported Ciphersuites:")
		fmt.Println(getSupportedCiphersuites())
		fmt.Println()
		fmt.Println("Example:")
		fmt.Println("  frost sign-share --keys keys.json --id 1 --commitments commitments.json --message 'Hello World'")
		fmt.Println("  frost sign-share --keys keys.json --id 1 --ciphersuite ed25519 --commitments commitments.json --message 'Hello World'")
	}

	if err := fs.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if *participantID == 0 {
		fmt.Fprintf(os.Stderr, "Error: participant id is required\n")
		fs.Usage()
		os.Exit(1)
	}

	if *message == "" {
		fmt.Fprintf(os.Stderr, "Error: message is required\n")
		fs.Usage()
		os.Exit(1)
	}

	// Set default filenames if not provided
	if *noncesFile == "" {
		*noncesFile = fmt.Sprintf("nonces-%d.json", *participantID)
	}
	if *output == "" {
		*output = fmt.Sprintf("share-%d.json", *participantID)
	}

	suite := getCiphersuite(*ciphersuiteFlag)
	grp := suite.Group()

	// Read key packages
	keysData, err := os.ReadFile(*keysFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading keys file: %v\n", err)
		os.Exit(1)
	}

	var keysInput struct {
		MinSigners     uint32             `json:"min_signers"`
		MaxSigners     uint32             `json:"max_signers"`
		GroupPublicKey string             `json:"group_public_key"`
		KeyPackages    []KeyPackageExport `json:"key_packages"`
	}

	if err := json.Unmarshal(keysData, &keysInput); err != nil {
		secmem.ZeroBytes(keysData)
		fmt.Fprintf(os.Stderr, "Error parsing keys file: %v\n", err)
		os.Exit(1)
	}
	secmem.ZeroBytes(keysData)

	// Find participant's key package
	var keyPackage *frost.KeyPackage
	for _, pkg := range keysInput.KeyPackages {
		if pkg.Identifier == safeUintToUint16(*participantID) {
			secretBytes, err := hex.DecodeString(pkg.SecretShare)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error decoding secret share: %v\n", err)
				os.Exit(1)
			}
			secret, err := grp.DeserializeScalar(secretBytes)
			secmem.ZeroBytes(secretBytes)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error deserializing secret share: %v\n", err)
				os.Exit(1)
			}

			pubKeyBytes, err := hex.DecodeString(pkg.PublicKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error decoding public key: %v\n", err)
				os.Exit(1)
			}
			pubKey, err := grp.DeserializeElement(pubKeyBytes)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error deserializing public key: %v\n", err)
				os.Exit(1)
			}

			keyPackage = &frost.KeyPackage{
				Identifier:     frost.Identifier(pkg.Identifier),
				SecretShare:    secret,
				GroupPublicKey: pubKey,
			}
			break
		}
	}

	if keyPackage == nil {
		fmt.Fprintf(os.Stderr, "Error: participant %d not found in key packages\n", *participantID)
		os.Exit(1)
	}

	// Read private nonces
	noncesData, err := os.ReadFile(*noncesFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading nonces file: %v\n", err)
		os.Exit(1)
	}

	var noncesInput struct {
		Identifier   uint16 `json:"identifier"`
		HidingNonce  string `json:"hiding_nonce"`
		BindingNonce string `json:"binding_nonce"`
	}

	if err := json.Unmarshal(noncesData, &noncesInput); err != nil {
		secmem.ZeroBytes(noncesData)
		fmt.Fprintf(os.Stderr, "Error parsing nonces file: %v\n", err)
		os.Exit(1)
	}
	secmem.ZeroBytes(noncesData)

	hidingNonceBytes, err := hex.DecodeString(noncesInput.HidingNonce)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding hiding nonce: %v\n", err)
		os.Exit(1)
	}
	hidingNonce, err := grp.DeserializeScalar(hidingNonceBytes)
	secmem.ZeroBytes(hidingNonceBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deserializing hiding nonce: %v\n", err)
		os.Exit(1)
	}

	bindingNonceBytes, err := hex.DecodeString(noncesInput.BindingNonce)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding binding nonce: %v\n", err)
		os.Exit(1)
	}
	bindingNonce, err := grp.DeserializeScalar(bindingNonceBytes)
	secmem.ZeroBytes(bindingNonceBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deserializing binding nonce: %v\n", err)
		os.Exit(1)
	}

	nonces := frost.SigningNonces{
		HidingNonce:  hidingNonce,
		BindingNonce: bindingNonce,
	}

	// Read commitments from all participants
	commitmentsData, err := os.ReadFile(*commitmentsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading commitments file: %v\n", err)
		os.Exit(1)
	}

	var commitmentsInput []struct {
		Identifier        uint16 `json:"identifier"`
		HidingCommitment  string `json:"hiding_commitment"`
		BindingCommitment string `json:"binding_commitment"`
	}

	if err := json.Unmarshal(commitmentsData, &commitmentsInput); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing commitments file: %v\n", err)
		os.Exit(1)
	}

	commitments := make(frost.CommitmentList, len(commitmentsInput))
	for i, c := range commitmentsInput {
		hidingCommBytes, err := hex.DecodeString(c.HidingCommitment)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decoding hiding commitment: %v\n", err)
			os.Exit(1)
		}
		hidingComm, err := grp.DeserializeElement(hidingCommBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error deserializing hiding commitment: %v\n", err)
			os.Exit(1)
		}

		bindingCommBytes, err := hex.DecodeString(c.BindingCommitment)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decoding binding commitment: %v\n", err)
			os.Exit(1)
		}
		bindingComm, err := grp.DeserializeElement(bindingCommBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error deserializing binding commitment: %v\n", err)
			os.Exit(1)
		}

		commitments[i] = frost.SigningCommitments{
			Identifier:             frost.Identifier(c.Identifier),
			HidingNonceCommitment:  hidingComm,
			BindingNonceCommitment: bindingComm,
		}
	}

	// Create signature share
	participant := signing.NewParticipant(*keyPackage, suite)
	messageBytes := []byte(*message)
	signatureShare, err := participant.RoundTwo(nonces, messageBytes, commitments)
	nonces.Zeroize()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating signature share: %v\n", err)
		os.Exit(1)
	}

	// Save signature share
	shareOutput := struct {
		Identifier uint16 `json:"identifier"`
		Share      string `json:"share"`
	}{
		Identifier: safeUint32ToUint16(uint32(signatureShare.Identifier)),
		Share:      hex.EncodeToString(signatureShare.SignatureShare.Bytes()),
	}

	shareData, err := json.MarshalIndent(shareOutput, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling signature share: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*output, shareData, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing signature share file: %v\n", err)
		os.Exit(1)
	}

	// Zero the hex-encoded secret share strings from parsed keys input
	for i := range keysInput.KeyPackages {
		secmem.ZeroString(&keysInput.KeyPackages[i].SecretShare)
	}

	// Zero the hex-encoded nonce strings from parsed nonces input
	secmem.ZeroString(&noncesInput.HidingNonce)
	secmem.ZeroString(&noncesInput.BindingNonce)

	fmt.Printf("Round 2 completed for participant %d\n", *participantID)
	fmt.Printf("Signature share saved to: %s\n", *output)
}

func aggregateCommand() {
	fs := flag.NewFlagSet("aggregate", flag.ExitOnError)
	keysFile := fs.String("keys", "frost-keys.json", "Input file containing key packages")
	commitmentsFile := fs.String("commitments", "commitments.json", "Input file containing all commitments")
	sharesFile := fs.String("shares", "shares.json", "Input file containing all signature shares")
	message := fs.String("message", "", "Message that was signed")
	output := fs.String("output", "frost-signature.json", "Output file for final signature")
	ciphersuiteFlag := fs.String("ciphersuite", "ristretto255", "Ciphersuite to use")

	fs.Usage = func() {
		fmt.Println("Usage: frost aggregate [options]")
		fmt.Println()
		fmt.Println("Aggregate signature shares into final signature")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Supported Ciphersuites:")
		fmt.Println(getSupportedCiphersuites())
		fmt.Println()
		fmt.Println("Example:")
		fmt.Println("  frost aggregate --keys keys.json --commitments commitments.json --shares shares.json --message 'Hello World'")
		fmt.Println("  frost aggregate --keys keys.json --ciphersuite ed25519 --commitments commitments.json --shares shares.json --message 'Hello World'")
	}

	if err := fs.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if *message == "" {
		fmt.Fprintf(os.Stderr, "Error: message is required\n")
		fs.Usage()
		os.Exit(1)
	}

	suite := getCiphersuite(*ciphersuiteFlag)
	grp := suite.Group()

	// Read key packages
	keysData, err := os.ReadFile(*keysFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading keys file: %v\n", err)
		os.Exit(1)
	}

	var keysInput struct {
		MinSigners     uint32             `json:"min_signers"`
		MaxSigners     uint32             `json:"max_signers"`
		GroupPublicKey string             `json:"group_public_key"`
		KeyPackages    []KeyPackageExport `json:"key_packages"`
	}

	if err := json.Unmarshal(keysData, &keysInput); err != nil {
		secmem.ZeroBytes(keysData)
		fmt.Fprintf(os.Stderr, "Error parsing keys file: %v\n", err)
		os.Exit(1)
	}
	secmem.ZeroBytes(keysData)

	// Parse group public key
	groupPubKeyBytes, err := hex.DecodeString(keysInput.GroupPublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding group public key: %v\n", err)
		os.Exit(1)
	}
	groupPublicKey, err := grp.DeserializeElement(groupPubKeyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deserializing group public key: %v\n", err)
		os.Exit(1)
	}

	// Read commitments
	commitmentsData, err := os.ReadFile(*commitmentsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading commitments file: %v\n", err)
		os.Exit(1)
	}

	var commitmentsInput []struct {
		Identifier        uint16 `json:"identifier"`
		HidingCommitment  string `json:"hiding_commitment"`
		BindingCommitment string `json:"binding_commitment"`
	}

	if err := json.Unmarshal(commitmentsData, &commitmentsInput); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing commitments file: %v\n", err)
		os.Exit(1)
	}

	commitments := make(frost.CommitmentList, len(commitmentsInput))
	for i, c := range commitmentsInput {
		hidingCommBytes, err := hex.DecodeString(c.HidingCommitment)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decoding hiding commitment: %v\n", err)
			os.Exit(1)
		}
		hidingComm, err := grp.DeserializeElement(hidingCommBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error deserializing hiding commitment: %v\n", err)
			os.Exit(1)
		}

		bindingCommBytes, err := hex.DecodeString(c.BindingCommitment)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decoding binding commitment: %v\n", err)
			os.Exit(1)
		}
		bindingComm, err := grp.DeserializeElement(bindingCommBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error deserializing binding commitment: %v\n", err)
			os.Exit(1)
		}

		commitments[i] = frost.SigningCommitments{
			Identifier:             frost.Identifier(c.Identifier),
			HidingNonceCommitment:  hidingComm,
			BindingNonceCommitment: bindingComm,
		}
	}

	// Read signature shares
	sharesData, err := os.ReadFile(*sharesFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading shares file: %v\n", err)
		os.Exit(1)
	}

	var sharesInput []struct {
		Identifier uint16 `json:"identifier"`
		Share      string `json:"share"`
	}

	if err := json.Unmarshal(sharesData, &sharesInput); err != nil {
		secmem.ZeroBytes(sharesData)
		fmt.Fprintf(os.Stderr, "Error parsing shares file: %v\n", err)
		os.Exit(1)
	}
	secmem.ZeroBytes(sharesData)

	signatureShares := make([]frost.SignatureShare, len(sharesInput))
	for i, s := range sharesInput {
		shareBytes, err := hex.DecodeString(s.Share)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decoding signature share: %v\n", err)
			os.Exit(1)
		}
		share, err := grp.DeserializeScalar(shareBytes)
		secmem.ZeroBytes(shareBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error deserializing signature share: %v\n", err)
			os.Exit(1)
		}

		signatureShares[i] = frost.SignatureShare{
			Identifier:     frost.Identifier(s.Identifier),
			SignatureShare: share,
		}
	}

	// Aggregate signature
	aggregator := signing.NewAggregator(suite, keysInput.MinSigners)
	messageBytes := []byte(*message)
	signature, err := aggregator.Aggregate(groupPublicKey, commitments, messageBytes, signatureShares)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error aggregating signature: %v\n", err)
		os.Exit(1)
	}

	// Save final signature
	sigOutput := struct {
		Message   string `json:"message"`
		Signature string `json:"signature"`
		PublicKey string `json:"public_key"`
	}{
		Message:   *message,
		Signature: hex.EncodeToString(append(signature.R.Bytes(), signature.Z.Bytes()...)),
		PublicKey: hex.EncodeToString(groupPublicKey.Bytes()),
	}

	sigData, err := json.MarshalIndent(sigOutput, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling signature: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*output, sigData, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing signature file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Signature aggregation completed successfully\n")
	fmt.Printf("Message: %s\n", *message)
	fmt.Printf("Signature: %s\n", hex.EncodeToString(append(signature.R.Bytes(), signature.Z.Bytes()...)))
	fmt.Printf("Signature saved to: %s\n", *output)
}

func verifyCommand() {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	sigFile := fs.String("signature", "frost-signature.json", "Input file containing signature")
	ciphersuiteFlag := fs.String("ciphersuite", "ristretto255", "Ciphersuite to use")

	fs.Usage = func() {
		fmt.Println("Usage: frost verify [options]")
		fmt.Println()
		fmt.Println("Verify a threshold signature")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Supported Ciphersuites:")
		fmt.Println(getSupportedCiphersuites())
		fmt.Println()
		fmt.Println("Example:")
		fmt.Println("  frost verify --signature sig.json")
		fmt.Println("  frost verify --signature sig.json --ciphersuite ed25519")
	}

	if err := fs.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	// Read signature file
	sigData, err := os.ReadFile(*sigFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading signature file: %v\n", err)
		os.Exit(1)
	}

	var sigInput struct {
		Message   string `json:"message"`
		Signature string `json:"signature"`
		PublicKey string `json:"public_key"`
	}

	if err := json.Unmarshal(sigData, &sigInput); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing signature file: %v\n", err)
		os.Exit(1)
	}

	suite := getCiphersuite(*ciphersuiteFlag)
	grp := suite.Group()

	// Parse public key
	pubKeyBytes, err := hex.DecodeString(sigInput.PublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding public key: %v\n", err)
		os.Exit(1)
	}
	publicKey, err := grp.DeserializeElement(pubKeyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deserializing public key: %v\n", err)
		os.Exit(1)
	}

	// Parse signature
	sigBytes, err := hex.DecodeString(sigInput.Signature)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding signature: %v\n", err)
		os.Exit(1)
	}

	// Verify
	messageBytes := []byte(sigInput.Message)
	err = suite.VerifySignature(messageBytes, sigBytes, publicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Signature verification FAILED: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Signature verification SUCCEEDED\n")
	fmt.Printf("Message: %s\n", sigInput.Message)
	fmt.Printf("Signature: %s\n", sigInput.Signature)
}

func collectCommitmentsCommand() {
	fs := flag.NewFlagSet("collect-commitments", flag.ExitOnError)
	output := fs.String("output", "commitments.json", "Output file for combined commitments")
	pattern := fs.String("pattern", "commitment-*.json", "File pattern to match")

	fs.Usage = func() {
		fmt.Println("Usage: frost collect-commitments [options]")
		fmt.Println()
		fmt.Println("Collect all commitment files into a single JSON array")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Example:")
		fmt.Println("  frost collect-commitments --output commitments.json")
	}

	if err := fs.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	// Find all commitment files
	matches, err := filepath.Glob(*pattern)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding commitment files: %v\n", err)
		os.Exit(1)
	}

	if len(matches) == 0 {
		fmt.Fprintf(os.Stderr, "No commitment files found matching pattern: %s\n", *pattern)
		os.Exit(1)
	}

	// Collect all commitments
	var allCommitments []map[string]interface{}
	for _, file := range matches {
		//nolint:gosec // CLI intentionally reads user-specified files
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", file, err)
			os.Exit(1)
		}

		var commitment map[string]interface{}
		if err := json.Unmarshal(data, &commitment); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing %s: %v\n", file, err)
			os.Exit(1)
		}

		allCommitments = append(allCommitments, commitment)
	}

	// Write combined file
	combinedData, err := json.MarshalIndent(allCommitments, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling commitments: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*output, combinedData, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Collected %d commitments from files:\n", len(matches))
	for _, file := range matches {
		fmt.Printf("  - %s\n", file)
	}
	fmt.Printf("Combined commitments saved to: %s\n", *output)
}

func collectSharesCommand() {
	fs := flag.NewFlagSet("collect-shares", flag.ExitOnError)
	output := fs.String("output", "shares.json", "Output file for combined shares")
	pattern := fs.String("pattern", "share-*.json", "File pattern to match")

	fs.Usage = func() {
		fmt.Println("Usage: frost collect-shares [options]")
		fmt.Println()
		fmt.Println("Collect all signature share files into a single JSON array")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Example:")
		fmt.Println("  frost collect-shares --output shares.json")
	}

	if err := fs.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	// Find all share files
	matches, err := filepath.Glob(*pattern)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding share files: %v\n", err)
		os.Exit(1)
	}

	if len(matches) == 0 {
		fmt.Fprintf(os.Stderr, "No share files found matching pattern: %s\n", *pattern)
		os.Exit(1)
	}

	// Collect all shares
	var allShares []map[string]interface{}
	for _, file := range matches {
		//nolint:gosec // CLI intentionally reads user-specified files
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", file, err)
			os.Exit(1)
		}

		var share map[string]interface{}
		if err := json.Unmarshal(data, &share); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing %s: %v\n", file, err)
			os.Exit(1)
		}

		allShares = append(allShares, share)
	}

	// Write combined file
	combinedData, err := json.MarshalIndent(allShares, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling shares: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*output, combinedData, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Collected %d signature shares from files:\n", len(matches))
	for _, file := range matches {
		fmt.Printf("  - %s\n", file)
	}
	fmt.Printf("Combined shares saved to: %s\n", *output)
}
