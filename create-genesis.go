package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"io/ioutil"
	"math/big"
	"os"
	"reflect"
	"strings"
	"unicode"
	"unsafe"

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/common/systemcontract"
	"github.com/ethereum/go-ethereum/eth/tracers"

	_ "github.com/ethereum/go-ethereum/eth/tracers/native"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
)

type artifactData struct {
	Bytecode         string `json:"bytecode"`
	DeployedBytecode string `json:"deployedBytecode"`
}

type dummyChainContext struct {
}

func (d *dummyChainContext) Engine() consensus.Engine {
	return nil
}

func (d *dummyChainContext) GetHeader(common.Hash, uint64) *types.Header {
	return nil
}

func createExtraData(validators []common.Address) []byte {
	extra := make([]byte, 32+20*len(validators)+65)
	for i, v := range validators {
		copy(extra[32+20*i:], v.Bytes())
	}
	return extra
}

func readDirtyStorageFromState(f *state.StateObject) state.Storage {
	var result map[common.Hash]common.Hash
	rs := reflect.ValueOf(*f)
	rf := rs.FieldByName("dirtyStorage")
	rs2 := reflect.New(rs.Type()).Elem()
	rs2.Set(rs)
	rf = rs2.FieldByName("dirtyStorage")
	rf = reflect.NewAt(rf.Type(), unsafe.Pointer(rf.UnsafeAddr())).Elem()
	ri := reflect.ValueOf(&result).Elem()
	ri.Set(rf)
	return result
}

func simulateSystemContract(genesis *core.Genesis, systemContract common.Address, rawArtifact []byte, constructor []byte, balance *big.Int) error {
	artifact := &artifactData{}
	if err := json.Unmarshal(rawArtifact, artifact); err != nil {
		return err
	}
	bytecode := append(hexutil.MustDecode(artifact.Bytecode), constructor...)
	// simulate constructor execution
	ethdb := rawdb.NewDatabase(memorydb.New())
	db := state.NewDatabaseWithConfig(ethdb, &trie.Config{})
	statedb, err := state.New(common.Hash{}, db, nil)
	if err != nil {
		return err
	}
	statedb.SetBalance(systemContract, balance)
	block := genesis.ToBlock(nil)
	blockContext := core.NewEVMBlockContext(block.Header(), &dummyChainContext{}, &common.Address{})
	txContext := core.NewEVMTxContext(
		types.NewMessage(common.Address{}, &systemContract, 0, big.NewInt(0), 10_000_000, big.NewInt(0), []byte{}, nil, false),
	)
	tracer, err := tracers.New("callTracer", nil)
	if err != nil {
		return err
	}
	evm := vm.NewEVM(blockContext, txContext, statedb, genesis.Config, vm.Config{
		Debug:  true,
		Tracer: tracer,
	})
	deployedBytecode, _, err := evm.CreateWithAddress(vm.AccountRef(common.Address{}), bytecode, 10_000_000, big.NewInt(0), systemContract)
	if err != nil {
		for _, c := range deployedBytecode[64:] {
			if c >= 32 && c <= unicode.MaxASCII {
				print(string(c))
			}
		}
		println()
		return err
	}
	storage := readDirtyStorageFromState(statedb.GetOrNewStateObject(systemContract))
	// read state changes from state database
	genesisAccount := core.GenesisAccount{
		Code:    deployedBytecode,
		Storage: storage.Copy(),
		Balance: big.NewInt(0),
		Nonce:   0,
	}
	if genesis.Alloc == nil {
		genesis.Alloc = make(core.GenesisAlloc)
	}
	genesis.Alloc[systemContract] = genesisAccount
	// make sure ctor working fine (better to fail here instead of in consensus engine)
	errorCode, _, err := evm.Call(vm.AccountRef(common.Address{}), systemContract, hexutil.MustDecode("0xe1c7392a"), 10_000_000, big.NewInt(0))
	if err != nil {
		for _, c := range errorCode[64:] {
			if c >= 32 && c <= unicode.MaxASCII {
				print(string(c))
			}
		}
		println()
		return err
	}
	return nil
}

var stakingAddress = common.HexToAddress("0x0000000000000000000000000000000000001000")
var slashingIndicatorAddress = common.HexToAddress("0x0000000000000000000000000000000000001001")
var systemRewardAddress = common.HexToAddress("0x0000000000000000000000000000000000001002")
var stakingPoolAddress = common.HexToAddress("0x0000000000000000000000000000000000007001")
var governanceAddress = common.HexToAddress("0x0000000000000000000000000000000000007002")
var chainConfigAddress = common.HexToAddress("0x0000000000000000000000000000000000007003")
var runtimeUpgradeAddress = common.HexToAddress("0x0000000000000000000000000000000000007004")
var deployerProxyAddress = common.HexToAddress("0x0000000000000000000000000000000000007005")
var intermediarySystemAddress = common.HexToAddress("0xfffffffffffffffffffffffffffffffffffffffe")

//go:embed build/contracts/Staking.json
var stakingRawArtifact []byte

//go:embed build/contracts/StakingPool.json
var stakingPoolRawArtifact []byte

//go:embed build/contracts/ChainConfig.json
var chainConfigRawArtifact []byte

//go:embed build/contracts/SlashingIndicator.json
var slashingIndicatorRawArtifact []byte

//go:embed build/contracts/SystemReward.json
var systemRewardRawArtifact []byte

//go:embed build/contracts/Governance.json
var governanceRawArtifact []byte

//go:embed build/contracts/RuntimeUpgrade.json
var runtimeUpgradeRawArtifact []byte

//go:embed build/contracts/DeployerProxy.json
var deployerProxyRawArtifact []byte

func newArguments(typeNames ...string) abi.Arguments {
	var args abi.Arguments
	for i, tn := range typeNames {
		abiType, err := abi.NewType(tn, tn, nil)
		if err != nil {
			panic(err)
		}
		args = append(args, abi.Argument{Name: fmt.Sprintf("%d", i), Type: abiType})
	}
	return args
}

type consensusParams struct {
	ActiveValidatorsLength   uint32                `json:"activeValidatorsLength"`
	EpochBlockInterval       uint32                `json:"epochBlockInterval"`
	MisdemeanorThreshold     uint32                `json:"misdemeanorThreshold"`
	FelonyThreshold          uint32                `json:"felonyThreshold"`
	ValidatorJailEpochLength uint32                `json:"validatorJailEpochLength"`
	UndelegatePeriod         uint32                `json:"undelegatePeriod"`
	MinValidatorStakeAmount  *math.HexOrDecimal256 `json:"minValidatorStakeAmount"`
	MinStakingAmount         *math.HexOrDecimal256 `json:"minStakingAmount"`
}

type genesisConfig struct {
	ChainId  int64 `json:"chainId"`
	Features struct {
		RuntimeUpgradeBlock *math.HexOrDecimal256 `json:"runtimeUpgradeBlock"`
	} `json:"features"`
	Deployers       []common.Address          `json:"deployers"`
	Validators      []common.Address          `json:"validators"`
	SystemTreasury  map[common.Address]uint16 `json:"systemTreasury"`
	ConsensusParams consensusParams           `json:"consensusParams"`
	VotingPeriod    int64                     `json:"votingPeriod"`
	Faucet          map[common.Address]string `json:"faucet"`
	CommissionRate  int64                     `json:"commissionRate"`
	InitialStakes   map[common.Address]string `json:"initialStakes"`
}

func invokeConstructorOrPanic(genesis *core.Genesis, contract common.Address, rawArtifact []byte, typeNames []string, params []interface{}, silent bool, balance *big.Int) {
	ctor, err := newArguments(typeNames...).Pack(params...)
	if err != nil {
		panic(err)
	}
	sig := crypto.Keccak256([]byte(fmt.Sprintf("ctor(%s)", strings.Join(typeNames, ","))))[:4]
	ctor = append(sig, ctor...)
	ctor, err = newArguments("bytes").Pack(ctor)
	if err != nil {
		panic(err)
	}
	if !silent {
		fmt.Printf(" + calling constructor: address=%s sig=%s ctor=%s\n", contract.Hex(), hexutil.Encode(sig), hexutil.Encode(ctor))
	}
	if err := simulateSystemContract(genesis, contract, rawArtifact, ctor, balance); err != nil {
		panic(err)
	}
}

func createGenesisConfig(config genesisConfig, targetFile string) error {
	genesis := defaultGenesisConfig(config)
	// extra data
	genesis.ExtraData = createExtraData(config.Validators)
	genesis.Config.Parlia.Epoch = uint64(config.ConsensusParams.EpochBlockInterval)
	// execute system contracts
	var initialStakes []*big.Int
	initialStakeTotal := big.NewInt(0)
	for _, v := range config.Validators {
		rawInitialStake, ok := config.InitialStakes[v]
		if !ok {
			return fmt.Errorf("initial stake is not found for validator: %s", v.Hex())
		}
		initialStake, err := hexutil.DecodeBig(rawInitialStake)
		if err != nil {
			return err
		}
		initialStakes = append(initialStakes, initialStake)
		initialStakeTotal.Add(initialStakeTotal, initialStake)
	}
	silent := targetFile == "stdout"
	invokeConstructorOrPanic(genesis, stakingAddress, stakingRawArtifact, []string{"address[]", "uint256[]", "uint16"}, []interface{}{
		config.Validators,
		initialStakes,
		uint16(config.CommissionRate),
	}, silent, initialStakeTotal)
	invokeConstructorOrPanic(genesis, chainConfigAddress, chainConfigRawArtifact, []string{"uint32", "uint32", "uint32", "uint32", "uint32", "uint32", "uint256", "uint256"}, []interface{}{
		config.ConsensusParams.ActiveValidatorsLength,
		config.ConsensusParams.EpochBlockInterval,
		config.ConsensusParams.MisdemeanorThreshold,
		config.ConsensusParams.FelonyThreshold,
		config.ConsensusParams.ValidatorJailEpochLength,
		config.ConsensusParams.UndelegatePeriod,
		(*big.Int)(config.ConsensusParams.MinValidatorStakeAmount),
		(*big.Int)(config.ConsensusParams.MinStakingAmount),
	}, silent, nil)
	invokeConstructorOrPanic(genesis, slashingIndicatorAddress, slashingIndicatorRawArtifact, []string{}, []interface{}{}, silent, nil)
	invokeConstructorOrPanic(genesis, stakingPoolAddress, stakingPoolRawArtifact, []string{}, []interface{}{}, silent, nil)
	var treasuryAddresses []common.Address
	var treasuryShares []uint16
	for k, v := range config.SystemTreasury {
		treasuryAddresses = append(treasuryAddresses, k)
		treasuryShares = append(treasuryShares, v)
	}
	invokeConstructorOrPanic(genesis, systemRewardAddress, systemRewardRawArtifact, []string{"address[]", "uint16[]"}, []interface{}{
		treasuryAddresses, treasuryShares,
	}, silent, nil)
	invokeConstructorOrPanic(genesis, governanceAddress, governanceRawArtifact, []string{"uint256"}, []interface{}{
		big.NewInt(config.VotingPeriod),
	}, silent, nil)
	invokeConstructorOrPanic(genesis, runtimeUpgradeAddress, runtimeUpgradeRawArtifact, []string{"address"}, []interface{}{
		systemcontract.EvmHookRuntimeUpgradeAddress,
	}, silent, nil)
	invokeConstructorOrPanic(genesis, deployerProxyAddress, deployerProxyRawArtifact, []string{"address[]"}, []interface{}{
		config.Deployers,
	}, silent, nil)
	// create system contract
	genesis.Alloc[intermediarySystemAddress] = core.GenesisAccount{
		Balance: big.NewInt(0),
	}
	// set staking allocation
	stakingAlloc := genesis.Alloc[stakingAddress]
	stakingAlloc.Balance = initialStakeTotal
	genesis.Alloc[stakingAddress] = stakingAlloc
	// apply faucet
	for key, value := range config.Faucet {
		balance, ok := new(big.Int).SetString(value[2:], 16)
		if !ok {
			return fmt.Errorf("failed to parse number (%s)", value)
		}
		genesis.Alloc[key] = core.GenesisAccount{
			Balance: balance,
		}
	}
	// save to file
	newJson, _ := json.MarshalIndent(genesis, "", "  ")
	if targetFile == "stdout" {
		_, err := os.Stdout.Write(newJson)
		return err
	} else if targetFile == "stderr" {
		_, err := os.Stderr.Write(newJson)
		return err
	}
	return ioutil.WriteFile(targetFile, newJson, fs.ModePerm)
}

func defaultGenesisConfig(config genesisConfig) *core.Genesis {
	chainConfig := &params.ChainConfig{
		ChainID:             big.NewInt(config.ChainId),
		HomesteadBlock:      big.NewInt(0),
		EIP150Block:         big.NewInt(0),
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		MuirGlacierBlock:    big.NewInt(0),
		RamanujanBlock:      big.NewInt(0),
		NielsBlock:          big.NewInt(0),
		MirrorSyncBlock:     big.NewInt(0),
		BrunoBlock:          big.NewInt(0),
		Parlia: &params.ParliaConfig{
			Period: 3,
			// epoch length is managed by consensus params
		},
	}
	// by default runtime upgrades are disabled
	if config.Features.RuntimeUpgradeBlock != nil {
		chainConfig.RuntimeUpgradeBlock = (*big.Int)(config.Features.RuntimeUpgradeBlock)
	}
	return &core.Genesis{
		Config:     chainConfig,
		Nonce:      0,
		Timestamp:  0x5e9da7ce,
		ExtraData:  nil,
		GasLimit:   0x2625a00,
		Difficulty: big.NewInt(0x01),
		Mixhash:    common.Hash{},
		Coinbase:   common.Address{},
		Alloc:      nil,
		Number:     0x00,
		GasUsed:    0x00,
		ParentHash: common.Hash{},
	}
}

var testnetConfig = genesisConfig{
	ChainId: 4131,
	// who is able to deploy smart contract from genesis block (it won't generate event log)
	Deployers: []common.Address{},
	// list of default validators (it won't generate event log)
	Validators: []common.Address{
		common.HexToAddress("0x43e063cebd504b63714864daf794b4b827406849"),
		common.HexToAddress("0x13708d393c0a3b4c305a2e5be5b21f5c32e58430"),
		common.HexToAddress("0x9b9a3c634a89c274d0aef028714e6ec84c042c9f"),
		common.HexToAddress("0xcf59c76188e8beb931b7664e6a4c951b16755b4e"),
		common.HexToAddress("0x8ba785c242802b977b5d17623a387489e313922b"),
		common.HexToAddress("0x961b82441e5566474720287479486dda962e7eb6"),
		common.HexToAddress("0x01dcd7275188105bfca76370bd570e4200f87781"),
	},
	SystemTreasury: map[common.Address]uint16{
		common.HexToAddress("0x55405f4c03e9649f092ebe874753eab47d1e6af4"): 10000,
	},
	ConsensusParams: consensusParams{
		ActiveValidatorsLength:   25,   // suggested values are (3k+1, where k is honest validators, even better): 7, 13, 19, 25, 31...
		EpochBlockInterval:       1200, // better to use 1 day epoch (86400/3=28800, where 3s is block time)
		MisdemeanorThreshold:     50,   // after missing this amount of blocks per day validator losses all daily rewards (penalty)
		FelonyThreshold:          150,  // after missing this amount of blocks per day validator goes in jail for N epochs
		ValidatorJailEpochLength: 7,    // how many epochs validator should stay in jail (7 epochs = ~7 days)
		UndelegatePeriod:         6,    // allow claiming funds only after 6 epochs (~7 days)

		MinValidatorStakeAmount: (*math.HexOrDecimal256)(hexutil.MustDecodeBig("0x3635c9adc5dea00000")), // 1000 // how many tokens validator must stake to create a validator (in ether)
		MinStakingAmount:        (*math.HexOrDecimal256)(hexutil.MustDecodeBig("0x64")), // 10 // minimum staking amount for delegators (in ether)
	},
	InitialStakes: map[common.Address]string{
		common.HexToAddress("0x43e063cebd504b63714864daf794b4b827406849"): "0x3635c9adc5dea00000", // 1000 eth
		common.HexToAddress("0x13708d393c0a3b4c305a2e5be5b21f5c32e58430"): "0x3635c9adc5dea00000", // 1000 eth
		common.HexToAddress("0x9b9a3c634a89c274d0aef028714e6ec84c042c9f"): "0x3635c9adc5dea00000", // 1000 eth
		common.HexToAddress("0xcf59c76188e8beb931b7664e6a4c951b16755b4e"): "0x3635c9adc5dea00000", // 1000 eth
		common.HexToAddress("0x8ba785c242802b977b5d17623a387489e313922b"): "0x3635c9adc5dea00000", // 1000 eth
		common.HexToAddress("0x961b82441e5566474720287479486dda962e7eb6"): "0x3635c9adc5dea00000", // 1000 eth
		common.HexToAddress("0x01dcd7275188105bfca76370bd570e4200f87781"): "0x3635c9adc5dea00000", // 1000 eth
	},
	// owner of the governance
	VotingPeriod: 60, // 3 minutes
	// faucet
	Faucet: map[common.Address]string{
		common.HexToAddress("0x43e063cebd504b63714864daf794b4b827406849"): "0x2E874EE4A84B300EDA00000", // governance (899,993,000)
		common.HexToAddress("0x13708d393c0a3b4c305a2e5be5b21f5c32e58430"): "0x52B7D2DCC80CD2E4000000", // faucet (100M)
	},
}

func main() {
	args := os.Args[1:]
	if len(args) > 0 {
		fileContents, err := os.ReadFile(args[0])
		if err != nil {
			panic(err)
		}
		genesis := &genesisConfig{}
		err = json.Unmarshal(fileContents, genesis)
		if err != nil {
			panic(err)
		}
		outputFile := "stdout"
		if len(args) > 1 {
			outputFile = args[1]
		}
		err = createGenesisConfig(*genesis, outputFile)
		if err != nil {
			panic(err)
		}
		return
	}
	
	fmt.Printf("\nbuilding dev net\n")
	if err := createGenesisConfig(testnetConfig, "testnet.json"); err != nil {
		panic(err)
	}
	fmt.Printf("\n")
}
