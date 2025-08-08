## EntryPoint Contract Documentation

The `EntryPointUpgradeable` contract serves as the central coordination mechanism for the Dogecoin bridge system. It manages proposers, handles TSS (Threshold Signature Scheme) verification, and provides a secure entry point for executing bridge operations.

### Overview

The EntryPoint contract implements a permissioned execution system where:

- **Proposers**: Authorized addresses that can submit transactions
- **TSS Signer**: A threshold signature scheme signer that validates operations
- **Submitter Rotation**: Automatic rotation of who can submit transactions
- **Staking Mechanism**: Economic security through staking requirements

### Key Features

- **Upgradeable**: Built with OpenZeppelin's upgradeable pattern
- **Reentrancy Protection**: Guards against reentrancy attacks
- **Ownable**: Admin functions restricted to owner
- **Staking System**: Economic incentives and security through staking
- **TSS Verification**: Cryptographic signature verification for all operations

### Architecture

#### Core Components

1. **Proposer Management**

   - List of authorized proposers
   - Add/remove proposer functionality
   - Pending proposer confirmation system

2. **Submitter Rotation**

   - Random selection from proposer pool after each successful submission
   - Time-based window `FORCE_ROTATION_WINDOW`: before it elapses, only `nextSubmitter` may submit; after it elapses, any proposer may submit

3. **Staking System**

   - Stake/unstake functionality
   - Minimum stake thresholds
   - Economic security model

4. **TSS Integration**
   - Signature verification for all operations
   - Nonce management to prevent replay attacks
   - Chain ID inclusion for cross-chain security

### Usage Guide

#### 1. Contract Initialization

```solidity
// Deploy the contract
EntryPointUpgradeable entryPoint = new EntryPointUpgradeable(stakeTokenAddress);

// Initialize with owner, TSS signer, and initial proposers
address[] memory initialProposers = new address[](1);
initialProposers[0] = proposerAddress;
entryPoint.initialize(ownerAddress, tssSignerAddress, initialProposers);
```

#### 2. Staking Operations

```solidity
// Stake tokens to become eligible for submission
uint256 stakeAmount = 1000 * 10**18; // 1000 tokens
IERC20(stakeToken).approve(address(entryPoint), stakeAmount);
entryPoint.stake(stakeAmount);

// Unstake tokens
entryPoint.unstake(stakeAmount);
```

#### 3. Executing Transactions via EntryPoint

The main function for executing bridge operations is `verifyAndCall`. Here's how to use it:

```solidity
// Prepare the transaction data
address[] memory targets = new address[](1);
targets[0] = address(dogechain);

bytes[] memory callDatas = new bytes[](1);
callDatas[0] = abi.encodeWithSelector(
    dogechain.submitBatch.selector,
    blockNumber,
    blockCount,
    merkleRoot
);

// Create the signature data
bytes memory encodedData = abi.encode(
    targets,
    callDatas,
    entryPoint.tssNonce(),
    block.chainid
);

// Generate signature (this should be done by TSS signer)
bytes32 digest = keccak256(encodedData).toEthSignedMessageHash();
bytes memory signature = generateSignature(digest, tssPrivateKey);

// Execute the transaction
bool[] memory results = entryPoint.verifyAndCall(targets, callDatas, signature);
```

#### 4. Proposer Management

```solidity
// Request to add/remove a proposer (owner only)
entryPoint.proposerRequest(newProposerAddress);

// Confirm proposer change (requires TSS signature)
bytes memory signature = generateProposerSignature(newProposerAddress);
entryPoint.proposerConfirm(newProposerAddress, signature);
```

### API Reference

#### Core Functions

##### `initialize(address _owner, address _tssSigner, address[] calldata _initialProposers)`

Initializes the contract with owner, TSS signer, and initial proposers.

##### `stake(uint256 _amount)`

Stakes tokens to become eligible for transaction submission.

##### `unstake(uint256 _amount)`

Unstakes previously staked tokens.

##### `verifyAndCall(address[] calldata _targets, bytes[] calldata _calldata, bytes calldata _signature)`

Main entry point for executing transactions. Requires:

- Caller to be the current submitter
- Sufficient staked amount
- Valid TSS signature

##### `setStakeThreshold(uint256 _newThreshold, bytes calldata _signature)`

Updates the minimum stake threshold (submitter only).

##### `setSignerAddress(address _newSigner, bytes calldata _signature)`

Updates the TSS signer address (submitter only).

<!-- chooseNewSubmitter has been removed; rotation is automatic in `checkSubmitter` and `_rotateSubmitter()` -->

#### Proposer Management

##### `proposerRequest(address _proposer)`

Initiates an add/remove proposer action (owner only).

- If `_proposer` is not currently a proposer, an add request is created and `AddProposerRequested(proposer, timestamp)` is emitted.
- If `_proposer` is currently a proposer, a remove request is created and `RemoveProposerRequested(proposer, timestamp)` is emitted. Removal is subject to a cooldown window measured in transactions: `txId >= lastRemoveProposerTxId + PROPOSER_REMOVE_WINDOW`.

The request is finalized by `proposerConfirm`.

##### `proposerConfirm(address _proposer, bytes calldata _signature)`

Finalizes the pending proposer add/remove request with a valid TSS signature over `abi.encodePacked(_proposer, tssNonce++, block.chainid)`.

- If `_proposer` is not in the set, it is added.
- If `_proposer` is in the set, it is removed and `lastRemoveProposerTxId` is updated.

Emits `ProposerConfirmed(proposer, timestamp)` and resets `pendingProposer` to the sentinel `address(1)`.

#### View Functions

##### `tssNonce()`

Returns the current TSS nonce for signature generation.

##### `nextSubmitter()`

Returns the address of the current submitter.

##### `isProposer(address)`

Checks if an address is an authorized proposer.

##### `stakedAmounts(address)`

Returns the staked amount for a given address.

### Security Considerations

1. **Signature Verification**: All critical operations require valid TSS signatures
2. **Nonce Management**: Prevents replay attacks across different operations
3. **Chain ID Inclusion**: Ensures signatures are chain-specific
4. **Staking Requirements**: Economic security through minimum stake thresholds
5. **Submitter Rotation**: Prevents single points of failure
6. **Reentrancy Protection**: Guards against reentrancy attacks

### Events

- `Stake(address indexed staker, uint256 amount)`
- `Unstake(address indexed staker, uint256 amount)`
- `SetSigner(address indexed newSigner)`
- `StakeThresholdUpdated(uint256 newThreshold)`
- `SubmitterChosen(address indexed newSubmitter)`
- `SubmitterRotationRequested(address indexed requester, address indexed currentSubmitter)`
- `AddProposerRequested(address proposer, uint256 timestamp)`
- `RemoveProposerRequested(address proposer, uint256 timestamp)`
- `ProposerConfirmed(address proposer, uint256 timestamp)`

Note: `SubmitterRotationRequested` is declared in the interface but is not emitted in the current implementation; rotation happens automatically after successful submissions.

### Error Codes

- `IncorrectSubmitter(address sender, address submitter)`

### Testing Examples

See the test file `test/DogecoinBridge.t.sol` for comprehensive usage examples, including:

- Contract initialization
- Staking operations
- Transaction execution via `verifyAndCall`
- Proposer management
- Error handling scenarios

## Foundry

**Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust.**

Foundry consists of:

- **Forge**: Ethereum testing framework (like Truffle, Hardhat and DappTools).
- **Cast**: Swiss army knife for interacting with EVM smart contracts, sending transactions and getting chain data.
- **Anvil**: Local Ethereum node, akin to Ganache, Hardhat Network.
- **Chisel**: Fast, utilitarian, and verbose solidity REPL.
