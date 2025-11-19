// Package testvectors contains RFC 9591 test vectors for FROST validation.
package testvectors

// ParticipantData holds test vector data for a single participant.
type ParticipantData struct {
	Identifier               uint64
	Share                    string
	HidingNonceRandomness    string
	BindingNonceRandomness   string
	HidingNonce              string
	BindingNonce             string
	HidingNonceCommitment    string
	BindingNonceCommitment   string
	BindingFactorInput       string
	BindingFactor            string
	SignatureShare           string
}

// TestVector represents a complete RFC 9591 test vector.
type TestVector struct {
	Name                         string
	MaxParticipants              int
	MinParticipants              int
	NumParticipants              int
	ParticipantList              []uint64
	GroupSecretKey               string
	GroupPublicKey               string
	Message                      string
	SharePolynomialCoefficients  []string
	Participants                 map[uint64]*ParticipantData
	FinalSignature               string
}

// Ristretto255SHA512Vector returns the RFC 9591 Appendix E.3 test vector
// for FROST(ristretto255, SHA-512).
func Ristretto255SHA512Vector() *TestVector {
	return &TestVector{
		Name:                        "FROST(ristretto255, SHA-512)",
		MaxParticipants:             3,
		MinParticipants:             2,
		NumParticipants:             2,
		ParticipantList:             []uint64{1, 3},
		GroupSecretKey:              "1b25a55e463cfd15cf14a5d3acc3d15053f08da49c8afcf3ab265f2ebc4f970b",
		GroupPublicKey:              "e2a62f39eede11269e3bd5a7d97554f5ca384f9f6d3dd9c3c0d05083c7254f57",
		Message:                     "74657374",
		SharePolynomialCoefficients: []string{"410f8b744b19325891d73736923525a4f596c805d060dfb9c98009d34e3fec02"},
		Participants: map[uint64]*ParticipantData{
			1: {
				Identifier:             1,
				Share:                  "5c3430d391552f6e60ecdc093ff9f6f4488756aa6cebdbad75a768010b8f830e",
				HidingNonceRandomness:  "f595a133b4d95c6e1f79887220c8b275ce6277e7f68a6640e1e7140f9be2fb5c",
				BindingNonceRandomness: "34dd1001360e3513cb37bebfabe7be4a32c5bb91ba19fbd4360d039111f0fbdc",
				HidingNonce:            "214f2cabb86ed71427ea7ad4283b0fae26b6746c801ce824b83ceb2b99278c03",
				BindingNonce:           "c9b8f5e16770d15603f744f8694c44e335e8faef00dad182b8d7a34a62552f0c",
				HidingNonceCommitment:  "965def4d0958398391fc06d8c2d72932608b1e6255226de4fb8d972dac15fd57",
				BindingNonceCommitment: "ec5170920660820007ae9e1d363936659ef622f99879898db86e5bf1d5bf2a14",
				BindingFactorInput:     "e2a62f39eede11269e3bd5a7d97554f5ca384f9f6d3dd9c3c0d05083c7254f572889dde2854e26377a16caf77dfee5f6be8fe5b4c80318da84698a4161021b033911db5ef8205362701bc9ecd983027814abee94f46d094943a2f4b79a6e4d4603e52c435d8344554942a0a472d8ad84320585b8da3ae5b9ce31cd1903f795c1af66de22af1a45f652cd05ee446b1b4091aaccc91e2471cd18a85a659cecd11f0100000000000000000000000000000000000000000000000000000000000000",
				BindingFactor:          "8967fd70fa06a58e5912603317fa94c77626395a695a0e4e4efc4476662eba0c",
				SignatureShare:         "9285f875923ce7e0c491a592e9ea1865ec1b823ead4854b48c8a46287749ee09",
			},
			3: {
				Identifier:             3,
				Share:                  "f17e505f0e2581c6acfe54d3846a622834b5e7b50cad9a2109a97ba7a80d5c04",
				HidingNonceRandomness:  "daa0cf42a32617786d390e0c7edfbf2efbd428037069357b5173ae61d6dd5d5e",
				BindingNonceRandomness: "b4387e72b2e4108ce4168931cc2c7fcce5f345a5297368952c18b5fc8473f050",
				HidingNonce:            "3f7927872b0f9051dd98dd73eb2b91494173bbe0feb65a3e7e58d3e2318fa40f",
				BindingNonce:           "ffd79445fb8030f0a3ddd3861aa4b42b618759282bfe24f1f9304c7009728305",
				HidingNonceCommitment:  "480e06e3de182bf83489c45d7441879932fd7b434a26af41455756264fbd5d6e",
				BindingNonceCommitment: "3064746dfd3c1862ef58fc68c706da287dd925066865ceacc816b3a28c7b363b",
				BindingFactorInput:     "e2a62f39eede11269e3bd5a7d97554f5ca384f9f6d3dd9c3c0d05083c7254f572889dde2854e26377a16caf77dfee5f6be8fe5b4c80318da84698a4161021b033911db5ef8205362701bc9ecd983027814abee94f46d094943a2f4b79a6e4d4603e52c435d8344554942a0a472d8ad84320585b8da3ae5b9ce31cd1903f795c1af66de22af1a45f652cd05ee446b1b4091aaccc91e2471cd18a85a659cecd11f0300000000000000000000000000000000000000000000000000000000000000",
				BindingFactor:          "f2c1bb7c33a10511158c2f1766a4a5fadf9f86f2a92692ed333128277cc31006",
				SignatureShare:         "7cb211fe0e3d59d25db6e36b3fb32344794139602a7b24f1ae0dc4e26ad7b908",
			},
		},
		FinalSignature: "fc45655fbc66bbffad654ea4ce5fdae253a49a64ace25d9adb62010dd9fb25552164141787162e5b4cab915b4aa45d94655dbb9ed7c378a53b980a0be220a802",
	}
}
