// Copyright (c) 2014-2016 The btcsuite developers
// Copyright (c) 2015-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chaincfg

import (
	"time"

	"github.com/bitum-project/bitumd/wire"
)

// MainNetParams defines the network parameters for the main Bitum network.
var MainNetParams = Params{
	Name:        "mainnet",
	Net:         wire.MainNet,
	DefaultPort: "9208",
	DNSSeeds: []DNSSeed{
		{"dnsseed.bitum.io", true},
	},

	// Chain parameters
	GenesisBlock:             &genesisBlock,
	GenesisHash:              &genesisHash,
	PowLimit:                 mainPowLimit,
	PowLimitBits:             0x1d00ffff,
	ReduceMinDifficulty:      false,
	MinDiffReductionTime:     0, //time.Minute * 10, // ~99.3% chance to be mined before reduction
	GenerateSupported:        true,
	MaximumBlockSizes:        []int{393216},
	MaxTxSize:                393216,
	TargetTimePerBlock:       time.Minute * 5,
	WorkDiffAlpha:            1,
	WorkDiffWindowSize:       144,
	WorkDiffWindows:          20,
	TargetTimespan:           time.Minute * 5 * 144,
	RetargetAdjustmentFactor: 4,

	// Subsidy parameters.
	BaseSubsidy:              3119582664,
	MulSubsidy:               100,
	DivSubsidy:               101,
	SubsidyReductionInterval: 6144,
	WorkRewardProportion:     6,
	StakeRewardProportion:    3,
	BlockTaxProportion:       1,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: []Checkpoint{
		{100, newHashFromStr("000000005b24df7dd3dcdfbb4a90e4001963360b4181f4975e9b94a3d94039a8")},
		{500, newHashFromStr("000000001d5f634c9fda95180ccb472de9cbc7d25e3fea276b8b2706ea04a610")},
		{1000, newHashFromStr("000000000037c4bba623aa717b50e530a5f9fd891df815e2791cd0a3a233b782")},
		{2000, newHashFromStr("0000000000104f477a38499a5988c5ace7e155e9fb27554b955f3e22724736cc")},
		{3000, newHashFromStr("00000000000207e68b97cf74585aec083d3118a524f50a177615622bf0bb2b9c")},
		{4000, newHashFromStr("00000000001461c0cc9e88eca5a2e82029dddf240457d3a4b99725984a8362c2")},
		{9000, newHashFromStr("000000000000af2d102346b800d7b9fb9c9cfa71677fd3bcd77eb7b03d20a290")},
		{9583, newHashFromStr("000000000030279de3cc16ac237f264471d44e75c89efae4e9add41e9c50c0a5")},
		{15205, newHashFromStr("00000000000491397676a5d23416f91bfa20627b45b2b98ff76624355ea48479")},
		{15206, newHashFromStr("00000000000734a6f56365393663dcd6a1af9bf4b3cd76ab904e6164c56cb419")},
		{15207, newHashFromStr("0000000000041d1aa34a4e14b6fa9bc03e30b92d183e510877327954facfe01b")},
		{15208, newHashFromStr("00000000000fb4c1311fdf68219eba1fb8fd6906e1429c4010462d49567beb92")},
		{15209, newHashFromStr("00000000000ae7221b6299a344faa4a2f41ed59a73ef821df0a643fc5f420dc1")},
		{15210, newHashFromStr("00000000000157ac17952336cd1a824c2212f3c024bd5735b20462618109fb90")},
		{15211, newHashFromStr("00000000000c5b6a4e2eceeaaa1f871720ef54a0faa568352bb5729e20f221d0")},
		{15212, newHashFromStr("000000000005b4108b61fbc0a0195f895b9e49204ab1144fd400402f7f42c0cf")},
		{15213, newHashFromStr("000000000004bdf697d58b26711eee303a006de84c94b7e0417b4d79d16320f4")},
		{15214, newHashFromStr("00000000000c023aa3b6be75cbd1312c35f05e12209d2afbc59676e9bf46297c")},
		{15215, newHashFromStr("000000000008ba07ff10f3c9d8becd7826834a05dc84809ae93a6d01d476dc6a")},
		{15216, newHashFromStr("000000000010b308d741c056e5b1b5d73451463a8bc205deb8bbfff09a6c187f")},
		{15217, newHashFromStr("0000000000075cf305c75366b873b02242e837222c2ae4afb657a956bc0d3aef")},
		{15218, newHashFromStr("0000000000095e9b5590d2c5852b8c1e1b3f3a9b7c26c7edba4efbd0979e1c9c")},
		{15219, newHashFromStr("00000000000699eb91360c487660748610638fa74076e6751a7ce43a79c30625")},
		{15220, newHashFromStr("0000000000096ab0bb39799a7f67431c23925b919ac3056085f2264e403a9b65")},
		{15221, newHashFromStr("00000000000754d5e569646ee19e4e621608d3562bdfc06f1ed127b77626f5ff")},
		{15222, newHashFromStr("0000000000081d2552be005a87f6ef6077ce059de4b1c57544f6af91346a3116")},
		{15223, newHashFromStr("000000000003490f43ccfc41ef7274ceb10bb560781dc8ad46b13d35ec60f975")},
		{15224, newHashFromStr("000000000011b952ebe62fecb56216af2d54fbc2d0f6dc9b9e0fd0e7466cf895")},
	},

	// The miner confirmation window is defined as:
	//   target proof of work timespan / target proof of work spacing
	RuleChangeActivationQuorum:     4032, // 10 % of RuleChangeActivationInterval * TicketsPerBlock
	RuleChangeActivationMultiplier: 3,    // 75%
	RuleChangeActivationDivisor:    4,
	RuleChangeActivationInterval:   2016 * 4, // 4 weeks
	
	Deployments: map[uint32][]ConsensusDeployment{
			4: {{
				Vote: Vote{
					Id:          VoteIDLNSupport,
					Description: "Request developers begin work on Lightning Network (LN) integration",
					Mask:        0x0018,
					Choices: []Choice{{
						Id:          "abstain",
						Description: "abstain voting for change",
						Bits:        0x0000,
						IsAbstain:   true,
						IsNo:        false,
					}, {
						Id:          "no",
						Description: "no, do not work on integrating LN support",
						Bits:        0x0008,
						IsAbstain:   false,
						IsNo:        true,
					}, {
						Id:          "yes",
						Description: "yes, begin work on integrating LN support",
						Bits:        0x0010,
						IsAbstain:   false,
						IsNo:        false,
					}},
				},
				StartTime:  1493164800,
				ExpireTime: 1577836800,
			}, {
				Vote: Vote{
					Id:          VoteIDSDiffAlgorithm,
					Description: "Change stake difficulty algorithm as defined in DCP0001",
					Mask:        0x0006,
					Choices: []Choice{{
						Id:          "abstain",
						Description: "abstain voting for change",
						Bits:        0x0000,
						IsAbstain:   true,
						IsNo:        false,
					}, {
						Id:          "no",
						Description: "keep the existing algorithm",
						Bits:        0x0002,
						IsAbstain:   false,
						IsNo:        true,
					}, {
						Id:          "yes",
						Description: "change to the new algorithm",
						Bits:        0x0004,
						IsAbstain:   false,
						IsNo:        false,
					}},
				},
				StartTime:  1493164800,
				ExpireTime: 1577836800,
			}},
			5: {{
				Vote: Vote{
					Id:          VoteIDLNFeatures,
					Description: "Enable features defined in DCP0002 and DCP0003 necessary to support Lightning Network (LN)",
					Mask:        0x0006,
					Choices: []Choice{{
						Id:          "abstain",
						Description: "abstain voting for change",
						Bits:        0x0000,
						IsAbstain:   true,
						IsNo:        false,
					}, {
						Id:          "no",
						Description: "keep the existing consensus rules",
						Bits:        0x0002,
						IsAbstain:   false,
						IsNo:        true,
					}, {
						Id:          "yes",
						Description: "change to the new consensus rules",
						Bits:        0x0004,
						IsAbstain:   false,
						IsNo:        false,
					}},
				},
				StartTime:  1505260800,
				ExpireTime: 1577836800,
			}},
			6: {{
				Vote: Vote{
					Id:          VoteIDFixLNSeqLocks,
					Description: "Modify sequence lock handling as defined in DCP0004",
					Mask:        0x0006,
					Choices: []Choice{{
						Id:          "abstain",
						Description: "abstain voting for change",
						Bits:        0x0000,
						IsAbstain:   true,
						IsNo:        false,
					}, {
						Id:          "no",
						Description: "keep the existing consensus rules",
						Bits:        0x0002,
						IsAbstain:   false,
						IsNo:        true,
					}, {
						Id:          "yes",
						Description: "change to the new consensus rules",
						Bits:        0x0004,
						IsAbstain:   false,
						IsNo:        false,
					}},
				},
				StartTime:  1548633600,
				ExpireTime: 1577836800,
			}},
		},
	
	// Enforce current block version once majority of the network has
	// upgraded.
	// 75% (750 / 1000)
	// Reject previous block versions once a majority of the network has
	// upgraded.
	// 95% (950 / 1000)
	BlockEnforceNumRequired: 750,
	BlockRejectNumRequired:  950,
	BlockUpgradeNumToCheck:  1000,

	// AcceptNonStdTxs is a mempool param to either accept and relay
	// non standard txs to the network or reject them
	AcceptNonStdTxs: false,

	// Address encoding magics
	NetworkAddressPrefix: "B",
	PubKeyAddrID:         [2]byte{0x11, 0x86},
	PubKeyHashAddrID:     [2]byte{0x05, 0xa3},
	PKHEdwardsAddrID:     [2]byte{0x09, 0x1f},
	PKHSchnorrAddrID:     [2]byte{0x08, 0x01},
	ScriptHashAddrID:     [2]byte{0x07, 0x1a},
	PrivateKeyID:         [2]byte{0x06, 0xde},

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x01, 0xf3, 0xa5, 0xe3},
	HDPublicKeyID:  [4]byte{0x02, 0xf1, 0xa7, 0x17},

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	SLIP0044CoinType: 42, // SLIP0044, Bitum
	LegacyCoinType:   20, // for backwards compatibility

	// Bitum PoS parameters
	MinimumStakeDiff:        2 * 1e8, // 2 Coin
	TicketPoolSize:          8192,
	TicketsPerBlock:         5,
	TicketMaturity:          256,
	TicketExpiry:            40960, // 5*TicketPoolSize
	CoinbaseMaturity:        256,
	SStxChangeMaturity:      1,
	TicketPoolSizeWeight:    4,
	StakeDiffAlpha:          1, // Minimal
	StakeDiffWindowSize:     144,
	StakeDiffWindows:        20,
	StakeVersionInterval:    144 * 2 * 7, // ~1 week
	MaxFreshStakePerBlock:   20,          // 4*TicketsPerBlock
	StakeEnabledHeight:      256 + 256,   // CoinbaseMaturity + TicketMaturity
	StakeValidationHeight:   4096,        // ~14 days
	StakeBaseSigScript:      []byte{0x00, 0x00},
	StakeMajorityMultiplier: 3,
	StakeMajorityDivisor:    4,

	// Bitum organization related parameters
	// Organization address is B1xAWYg2eAyXhbetkLTMWmWN3Ub8AZfkeTq
	OrganizationPkScript:        hexDecode("76a914ca62b11e8a5ca4ea64616604adf12c819cfcc3f788ac"),
	OrganizationPkScriptVersion: 0,
	BlockOneLedger:              BlockOneLedgerMainNet,
}
