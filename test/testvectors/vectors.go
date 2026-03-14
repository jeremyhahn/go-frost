// Package testvectors contains RFC 9591 test vectors for FROST validation.
package testvectors

// ParticipantData holds test vector data for a single participant.
type ParticipantData struct {
	Identifier             uint64
	Share                  string
	HidingNonceRandomness  string
	BindingNonceRandomness string
	HidingNonce            string
	BindingNonce           string
	HidingNonceCommitment  string
	BindingNonceCommitment string
	BindingFactorInput     string
	BindingFactor          string
	SignatureShare         string
}

// TestVector represents a complete RFC 9591 test vector.
type TestVector struct {
	Name                        string
	MaxParticipants             int
	MinParticipants             int
	NumParticipants             int
	ParticipantList             []uint64
	GroupSecretKey              string
	GroupPublicKey              string
	Message                     string
	SharePolynomialCoefficients []string
	Participants                map[uint64]*ParticipantData
	FinalSignature              string
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

// Ed25519SHA512Vector returns the RFC 9591 Appendix E.1 test vector
// for FROST(Ed25519, SHA-512).
func Ed25519SHA512Vector() *TestVector {
	return &TestVector{
		Name:                        "FROST(Ed25519, SHA-512)",
		MaxParticipants:             3,
		MinParticipants:             2,
		NumParticipants:             2,
		ParticipantList:             []uint64{1, 3},
		GroupSecretKey:              "7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304",
		GroupPublicKey:              "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673",
		Message:                     "74657374",
		SharePolynomialCoefficients: []string{"178199860edd8c62f5212ee91eff1295d0d670ab4ed4506866bae57e7030b204"},
		Participants: map[uint64]*ParticipantData{
			1: {
				Identifier:             1,
				Share:                  "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509",
				HidingNonceRandomness:  "0fd2e39e111cdc266f6c0f4d0fd45c947761f1f5d3cb583dfcb9bbaf8d4c9fec",
				BindingNonceRandomness: "69cd85f631d5f7f2721ed5e40519b1366f340a87c2f6856363dbdcda348a7501",
				HidingNonce:            "812d6104142944d5a55924de6d49940956206909f2acaeedecda2b726e630407",
				BindingNonce:           "b1110165fc2334149750b28dd813a39244f315cff14d4e89e6142f262ed83301",
				HidingNonceCommitment:  "b5aa8ab305882a6fc69cbee9327e5a45e54c08af61ae77cb8207be3d2ce13de3",
				BindingNonceCommitment: "67e98ab55aa310c3120418e5050c9cf76cf387cb20ac9e4b6fdb6f82a469f932",
				BindingFactorInput:     "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673504df914fa965023fb75c25ded4bb260f417de6d32e5c442c6ba313791cc9a4948d6273e8d3511f93348ea7a708a9b862bc73ba2a79cfdfe07729a193751cbc973af46d8ac3440e518d4ce440a0e7d4ad5f62ca8940f32de6d8dc00fc12c660b817d587d82f856d277ce6473cae6d2f5763f7da2e8b4d799a3f3e725d4522ec70100000000000000000000000000000000000000000000000000000000000000",
				BindingFactor:          "f2cb9d7dd9beff688da6fcc83fa89046b3479417f47f55600b106760eb3b5603",
				SignatureShare:         "001719ab5a53ee1a12095cd088fd149702c0720ce5fd2f29dbecf24b7281b603",
			},
			3: {
				Identifier:             3,
				Share:                  "d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02",
				HidingNonceRandomness:  "86d64a260059e495d0fb4fcc17ea3da7452391baa494d4b00321098ed2a0062f",
				BindingNonceRandomness: "13e6b25afb2eba51716a9a7d44130c0dbae0004a9ef8d7b5550c8a0e07c61775",
				HidingNonce:            "c256de65476204095ebdc01bd11dc10e57b36bc96284595b8215222374f99c0e",
				BindingNonce:           "243d71944d929063bc51205714ae3c2218bd3451d0214dfb5aeec2a90c35180d",
				HidingNonceCommitment:  "cfbdb165bd8aad6eb79deb8d287bcc0ab6658ae57fdcc98ed12c0669e90aec91",
				BindingNonceCommitment: "7487bc41a6e712eea2f2af24681b58b1cf1da278ea11fe4e8b78398965f13552",
				BindingFactorInput:     "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673504df914fa965023fb75c25ded4bb260f417de6d32e5c442c6ba313791cc9a4948d6273e8d3511f93348ea7a708a9b862bc73ba2a79cfdfe07729a193751cbc973af46d8ac3440e518d4ce440a0e7d4ad5f62ca8940f32de6d8dc00fc12c660b817d587d82f856d277ce6473cae6d2f5763f7da2e8b4d799a3f3e725d4522ec70300000000000000000000000000000000000000000000000000000000000000",
				BindingFactor:          "b087686bf35a13f3dc78e780a34b0fe8a77fef1b9938c563f5573d71d8d7890f",
				SignatureShare:         "bd86125de990acc5e1f13781d8e32c03a9bbd4c53539bbc106058bfd14326007",
			},
		},
		FinalSignature: "36282629c383bb820a88b71cae937d41f2f2adfcc3d02e55507e2fb9e2dd3cbebd9d2b0844e49ae0f3fa935161e1419aab7b47d21a37ebeae1f17d4987b3160b",
	}
}

// Ed448SHAKE256Vector returns the RFC 9591 Appendix E.2 test vector
// for FROST(Ed448, SHAKE256).
func Ed448SHAKE256Vector() *TestVector {
	return &TestVector{
		Name:                        "FROST(Ed448, SHAKE256)",
		MaxParticipants:             3,
		MinParticipants:             2,
		NumParticipants:             2,
		ParticipantList:             []uint64{1, 3},
		GroupSecretKey:              "6298e1eef3c379392caaed061ed8a31033c9e9e3420726f23b404158a401cd9df24632adfe6b418dc942d8a091817dd8bd70e1c72ba52f3c00",
		GroupPublicKey:              "3832f82fda00ff5365b0376df705675b63d2a93c24c6e81d40801ba265632be10f443f95968fadb70d10786827f30dc001c8d0f9b7c1d1b000",
		Message:                     "74657374",
		SharePolynomialCoefficients: []string{"dbd7a514f7a731976620f0436bd135fe8dddc3fadd6e0d13dbd58a1981e587d377d48e0b7ce4e0092967c5e85884d0275a7a740b6abdcd0500"},
		Participants: map[uint64]*ParticipantData{
			1: {
				Identifier:             1,
				Share:                  "4a2b2f5858a932ad3d3b18bd16e76ced3070d72fd79ae4402df201f525e754716a1bc1b87a502297f2a99d89ea054e0018eb55d39562fd0100",
				HidingNonceRandomness:  "9cda90c98863ef3141b75f09375757286b4bc323dd61aeb45c07de45e4937bbd",
				BindingNonceRandomness: "781bf4881ffe1aa06f9341a747179f07a49745f8cd37d4696f226aa065683c0a",
				HidingNonce:            "f922beb51a5ac88d1e862278d89e12c05263b945147db04b9566acb2b5b0f7422ccea4f9286f4f80e6b646e72143eeaecc0e5988f8b2b93100",
				BindingNonce:           "1890f16a120cdeac092df29955a29c7cf29c13f6f7be60e63d63f3824f2d37e9c3a002dfefc232972dc08658a8c37c3ec06a0c5dc146150500",
				HidingNonceCommitment:  "3518c2246c874569e54ab254cb1da666ca30f7879605cc43b4d2c47a521f8b5716080ab723d3a0cd04b7e41f3cc1d3031c94ccf3829b23fe80",
				BindingNonceCommitment: "11b3d5220c57d02057497de3c4eebab384900206592d877059b0a5f1d5250d002682f0e22dff096c46bb81b46d60fcfe7752ed47cea76c3900",
				BindingFactorInput:     "3832f82fda00ff5365b0376df705675b63d2a93c24c6e81d40801ba265632be10f443f95968fadb70d10786827f30dc001c8d0f9b7c1d1b000e9a0f30b97fe77ef751b08d4e252a3719ae9135e7f7926f7e3b7dd6656b27089ca354997fe5a633aa0946c89f022462e7e9d50fd6ef313f72d956ea4571089427daa1862f623a41625177d91e4a8f350ce9c8bd3bc7c766515dc1dd3a0eab93777526b616cccb148fe1e5992dc1ae705c8ba2f97ca8983328d41d375ed1e5fde5c9d672121c9e8f177f4a1a9b2575961531b33f054451363c8f27618382cd66ce14ad93b68dac6a09f5edcbccc813906b3fc50b8fef1cc09757b06646f38ceed1674cd6ced28a59c93851b325c6a9ef6a4b3b88860b7138ee246034561c7460db0b3fae5010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				BindingFactor:          "71966390dfdbed73cf9b79486f3b70e23b243e6c40638fb55998642a60109daecbfcb879eed9fe7dbbed8d9e47317715a5740f772173342e00",
				SignatureShare:         "e1eb9bfbef792776b7103891032788406c070c5c315e3bf5d64acd46ea8855e85b53146150a09149665cbfec71626810b575e6f4dbe9ba3700",
			},
			3: {
				Identifier:             3,
				Share:                  "00db7a8146f995db0a7cf844ed89d8e94c2b5f259378ff66e39d172828b264185ac4decf7219e4aa4478285b9c0eef4fccdf3eea69dd980d00",
				HidingNonceRandomness:  "b3adf97ceea770e703ab295babf311d77e956a20d3452b4b3344aa89a828e6df",
				BindingNonceRandomness: "81dbe7742b0920930299197322b255734e52bbb91f50cfe8ce689f56fadbce31",
				HidingNonce:            "ccb5c1e82f23e0a4b966b824dbc7b0ef1cc5f56eeac2a4126e2b2143c5f3a4d890c52d27803abcf94927faf3fc405c0b2123a57a93cefa3b00",
				BindingNonce:           "e089df9bf311cf711e2a24ea27af53e07b846d09692fe11035a1112f04d8b7462a62f34d8c01493a22b57a1cbf1f0a46c77d64d46449a90100",
				HidingNonceCommitment:  "1254546d7d104c04e4fbcf29e05747e2edd392f6787d05a6216f3713ef859efe573d180d291e48411e5e3006e9f90ee986ccc26b7a42490b80",
				BindingNonceCommitment: "3ef0cec20be15e56b3ddcb6f7b956fca0c8f71990f45316b537b4f64c5e8763e6629d7262ff7cd0235d0781f23be97bf8fa8817643ea19cd00",
				BindingFactorInput:     "3832f82fda00ff5365b0376df705675b63d2a93c24c6e81d40801ba265632be10f443f95968fadb70d10786827f30dc001c8d0f9b7c1d1b000e9a0f30b97fe77ef751b08d4e252a3719ae9135e7f7926f7e3b7dd6656b27089ca354997fe5a633aa0946c89f022462e7e9d50fd6ef313f72d956ea4571089427daa1862f623a41625177d91e4a8f350ce9c8bd3bc7c766515dc1dd3a0eab93777526b616cccb148fe1e5992dc1ae705c8ba2f97ca8983328d41d375ed1e5fde5c9d672121c9e8f177f4a1a9b2575961531b33f054451363c8f27618382cd66ce14ad93b68dac6a09f5edcbccc813906b3fc50b8fef1cc09757b06646f38ceed1674cd6ced28a59c93851b325c6a9ef6a4b3b88860b7138ee246034561c7460db0b3fae5030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				BindingFactor:          "236a6f7239ac2019334bad21323ec93bef2fead37bd55114356419f3fc1fb59f797f44079f28b1a64f51dd0a113f90f2c3a1c27d2faa4f1300",
				SignatureShare:         "815434eb0b9f9242d54b8baf2141fe28976cabe5f441ccfcd5ee7cdb4b52185b02b99e6de28e2ab086c7764068c5a01b5300986b9f084f3e00",
			},
		},
		FinalSignature: "cd642cba59c449dad8e896a78a60e8edfcbd9040df524370891ff8077d47ce721d683874483795f0d85efcbd642c4510614328605a19c6ed806ffb773b6956419537cdfdb2b2a51948733de192dcc4b82dc31580a536db6d435e0cb3ce322fbcf9ec23362dda27092c08767e607bf2093600",
	}
}

// P256SHA256Vector returns the RFC 9591 Appendix E.4 test vector
// for FROST(P-256, SHA-256).
func P256SHA256Vector() *TestVector {
	return &TestVector{
		Name:                        "FROST(P-256, SHA-256)",
		MaxParticipants:             3,
		MinParticipants:             2,
		NumParticipants:             2,
		ParticipantList:             []uint64{1, 3},
		GroupSecretKey:              "8ba9bba2e0fd8c4767154d35a0b7562244a4aaf6f36c8fb8735fa48b301bd8de",
		GroupPublicKey:              "023a309ad94e9fe8a7ba45dfc58f38bf091959d3c99cfbd02b4dc00585ec45ab70",
		Message:                     "74657374",
		SharePolynomialCoefficients: []string{"80f25e6c0709353e46bfbe882a11bdbb1f8097e46340eb8673b7e14556e6c3a4"},
		Participants: map[uint64]*ParticipantData{
			1: {
				Identifier:             1,
				Share:                  "0c9c1a0fe806c184add50bbdcac913dda73e482daf95dcb9f35dbb0d8a9f7731",
				HidingNonceRandomness:  "ec4c891c85fee802a9d757a67d1252e7f4e5efb8a538991ac18fbd0e06fb6fd3",
				BindingNonceRandomness: "9334e29d09061223f69a09421715a347e4e6deba77444c8f42b0c833f80f4ef9",
				HidingNonce:            "9f0542a5ba879a58f255c09f06da7102ef6a2dec6279700c656d58394d8facd4",
				BindingNonce:           "6513dfe7429aa2fc972c69bb495b27118c45bbc6e654bb9dc9be55385b55c0d7",
				HidingNonceCommitment:  "0213b3e6298bf8ad46fd5e9389519a8665d63d98f4ec6a1fcca434e809d2d8070e",
				BindingNonceCommitment: "02188ff1390bf69374d7b272e454b1878ef10a6b6ea3ff36f114b300b4dbd5233b",
				BindingFactorInput:     "023a309ad94e9fe8a7ba45dfc58f38bf091959d3c99cfbd02b4dc00585ec45ab70825371853e974bc30ac5b947b216d70461919666584c70c51f9f56f117736c5d178dd0b521ad9c1abe98048419cbdec81504c85e12eb40e3bcb6ec73d3fc4afd0000000000000000000000000000000000000000000000000000000000000001",
				BindingFactor:          "7925f0d4693f204e6e59233e92227c7124664a99739d2c06b81cf64ddf90559e",
				SignatureShare:         "400308eaed7a2ddee02a265abe6a1cfe04d946ee8720768899619cfabe7a3aeb",
			},
			3: {
				Identifier:             3,
				Share:                  "0e80d6e8f6192c003b5488ce1eec8f5429587d48cf001541e713b2d53c09d928",
				HidingNonceRandomness:  "c0451c5a0a5480d6c1f860e5db7d655233dca2669fd90ff048454b8ce983367b",
				BindingNonceRandomness: "2ba5f7793ae700e40e78937a82f407dd35e847e33d1e607b5c7eb6ed2a8ed799",
				HidingNonce:            "f73444a8972bcda9e506bbca3d2b1c083c10facdf4bb5d47fef7c2dc1d9f2a0d",
				BindingNonce:           "44c6a29075d6e7e4f8b97796205f9e22062e7835141470afe9417fd317c1c303",
				HidingNonceCommitment:  "033ac9a5fe4a8b57316ba1c34e8a6de453033b750e8984924a984eb67a11e73a3f",
				BindingNonceCommitment: "03a7a2480ee16199262e648aea3acab628a53e9b8c1945078f2ddfbdc98b7df369",
				BindingFactorInput:     "023a309ad94e9fe8a7ba45dfc58f38bf091959d3c99cfbd02b4dc00585ec45ab70825371853e974bc30ac5b947b216d70461919666584c70c51f9f56f117736c5d178dd0b521ad9c1abe98048419cbdec81504c85e12eb40e3bcb6ec73d3fc4afd0000000000000000000000000000000000000000000000000000000000000003",
				BindingFactor:          "e10d24a8a403723bcb6f9bb4c537f316593683b472f7a89f166630dde11822c4",
				SignatureShare:         "561da3c179edbb0502d941bb3e3ace3c37d122aaa46fb54499f15f3a3331de44",
			},
		},
		FinalSignature: "026d8d434874f87bdb7bc0dfd239b2c00639044f9dcb195e9a04426f70bfa4b70d9620acac6767e8e3e3036815fca4eb3a3caa69992b902bcd3352fc34f1ac192f",
	}
}

// Secp256k1SHA256Vector returns the RFC 9591 Appendix E.5 test vector
// for FROST(secp256k1, SHA-256).
func Secp256k1SHA256Vector() *TestVector {
	return &TestVector{
		Name:                        "FROST(secp256k1, SHA-256)",
		MaxParticipants:             3,
		MinParticipants:             2,
		NumParticipants:             2,
		ParticipantList:             []uint64{1, 3},
		GroupSecretKey:              "0d004150d27c3bf2a42f312683d35fac7394b1e9e318249c1bfe7f0795a83114",
		GroupPublicKey:              "02f37c34b66ced1fb51c34a90bdae006901f10625cc06c4f64663b0eae87d87b4f",
		Message:                     "74657374",
		SharePolynomialCoefficients: []string{"fbf85eadae3058ea14f19148bb72b45e4399c0b16028acaf0395c9b03c823579"},
		Participants: map[uint64]*ParticipantData{
			1: {
				Identifier:             1,
				Share:                  "08f89ffe80ac94dcb920c26f3f46140bfc7f95b493f8310f5fc1ea2b01f4254c",
				HidingNonceRandomness:  "7ea5ed09af19f6ff21040c07ec2d2adbd35b759da5a401d4c99dd26b82391cb2",
				BindingNonceRandomness: "47acab018f116020c10cb9b9abdc7ac10aae1b48ca6e36dc15acb6ec9be5cdc5",
				HidingNonce:            "841d3a6450d7580b4da83c8e618414d0f024391f2aeb511d7579224420aa81f0",
				BindingNonce:           "8d2624f532af631377f33cf44b5ac5f849067cae2eacb88680a31e77c79b5a80",
				HidingNonceCommitment:  "03c699af97d26bb4d3f05232ec5e1938c12f1e6ae97643c8f8f11c9820303f1904",
				BindingNonceCommitment: "02fa2aaccd51b948c9dc1a325d77226e98a5a3fe65fe9ba213761a60123040a45e",
				BindingFactorInput:     "02f37c34b66ced1fb51c34a90bdae006901f10625cc06c4f64663b0eae87d87b4fff9b5210ffbb3c07a73a7c8935be4a8c62cf015f6cf7ade6efac09a6513540fc3f5a816aaebc2114a811a415d7a55db7c5cbc1cf27183e79dd9def941b5d48010000000000000000000000000000000000000000000000000000000000000001",
				BindingFactor:          "3e08fe561e075c653cbfd46908a10e7637c70c74f0a77d5fd45d1a750c739ec6",
				SignatureShare:         "c4fce1775a1e141fb579944166eab0d65eefe7b98d480a569bbbfcb14f91c197",
			},
			3: {
				Identifier:             3,
				Share:                  "00e95d59dd0d46b0e303e500b62b7ccb0e555d49f5b849f5e748c071da8c0dbc",
				HidingNonceRandomness:  "e6cc56ccbd0502b3f6f831d91e2ebd01c4de0479e0191b66895a4ffd9b68d544",
				BindingNonceRandomness: "7203d55eb82a5ca0d7d83674541ab55f6e76f1b85391d2c13706a89a064fd5b9",
				HidingNonce:            "2b19b13f193f4ce83a399362a90cdc1e0ddcd83e57089a7af0bdca71d47869b2",
				BindingNonce:           "7a443bde83dc63ef52dda354005225ba0e553243402a4705ce28ffaafe0f5b98",
				HidingNonceCommitment:  "03077507ba327fc074d2793955ef3410ee3f03b82b4cdc2370f71d865beb926ef6",
				BindingNonceCommitment: "02ad53031ddfbbacfc5fbda3d3b0c2445c8e3e99cbc4ca2db2aa283fa68525b135",
				BindingFactorInput:     "02f37c34b66ced1fb51c34a90bdae006901f10625cc06c4f64663b0eae87d87b4fff9b5210ffbb3c07a73a7c8935be4a8c62cf015f6cf7ade6efac09a6513540fc3f5a816aaebc2114a811a415d7a55db7c5cbc1cf27183e79dd9def941b5d48010000000000000000000000000000000000000000000000000000000000000003",
				BindingFactor:          "93f79041bb3fd266105be251adaeb5fd7f8b104fb554a4ba9a0becea48ddbfd7",
				SignatureShare:         "0160fd0d388932f4826d2ebcd6b9eaba734f7c71cf25b4279a4ca2581e47b18d",
			},
		},
		FinalSignature: "0205b6d04d3774c8929413e3c76024d54149c372d57aae62574ed74319b5ea14d0c65dde8492a7471437e6c2fe3da49b90d23f642b5c6dbe7e36089f096dd97324",
	}
}
