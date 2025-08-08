// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {IEntryPoint} from "./interfaces/IEntryPoint.sol";

/**
 * @dev Manage all onchain information.
 */
contract EntryPointUpgradeable is
    IEntryPoint,
    Initializable,
    ReentrancyGuardUpgradeable,
    OwnableUpgradeable
{
    /// @notice Time window after which any proposer may submit if the current submitter is inactive.
    uint256 public constant FORCE_ROTATION_WINDOW = 1 minutes;
    uint256 public constant MIN_PARTICIPANT_COUNT = 3;
    /// @notice Cooldown window measured in `txId` increments required between proposer removals.
    uint256 public constant PROPOSER_REMOVE_WINDOW = 3;
    address public immutable stakeToken;

    uint256 public txId;
    uint256 public lastSubmissionTime;
    /// @notice The `txId` value recorded at the time of the last proposer removal.
    uint256 public lastRemoveProposerTxId;
    uint256 public tssNonce;
    address public tssSigner;

    address[] public proposers;
    /// @notice Address for the pending proposer add/remove request. Uses sentinel `address(1)` when empty.
    address public pendingProposer;
    address public nextSubmitter;
    mapping(address => bool) public isProposer;

    uint256 public stakeThreshold;
    mapping(address => uint256) public stakedAmounts;

    /// @dev Restricts callers to the active submitter within the rotation window, or any proposer after it.
    ///      Also enforces that the caller has staked at least `stakeThreshold`. Always rotates submitter after.
    modifier checkSubmitter() {
        if (block.timestamp >= lastSubmissionTime + FORCE_ROTATION_WINDOW) {
            require(isProposer[msg.sender], "Not Proposer");
        } else {
            require(
                msg.sender == nextSubmitter,
                IncorrectSubmitter(msg.sender, nextSubmitter)
            );
        }
        require(
            stakedAmounts[msg.sender] >= stakeThreshold,
            "Submitter has no staked amount"
        );
        _;
        _rotateSubmitter();
    }

    constructor(address _stakeToken) {
        stakeToken = _stakeToken;
    }

    /**
     * @dev Initializes the contract.
     * @param _tssSigner The address of tssSigner.
     */
    function initialize(
        address _owner,
        address _tssSigner,
        address[] calldata _initialProposers
    ) public initializer {
        __ReentrancyGuard_init();
        __Ownable_init(_owner);
        require(_tssSigner != address(0), "Invalid Address");
        tssSigner = _tssSigner;
        lastSubmissionTime = block.timestamp;
        proposers = _initialProposers;
        for (uint256 i; i < _initialProposers.length; ++i) {
            isProposer[_initialProposers[i]] = true;
        }
        nextSubmitter = _getRandomProposer(nextSubmitter);
        emit SubmitterChosen(nextSubmitter);
    }

    function stake(uint256 _amount) external {
        require(_amount > 0, "Invalid Amount");
        IERC20(stakeToken).transferFrom(msg.sender, address(this), _amount);
        stakedAmounts[msg.sender] += _amount;
        emit Stake(msg.sender, _amount);
    }

    function unstake(uint256 _amount) external {
        require(
            stakedAmounts[msg.sender] >= _amount,
            "Insufficient Staked Amount"
        );
        stakedAmounts[msg.sender] -= _amount;
        IERC20(stakeToken).transfer(msg.sender, _amount);
        emit Unstake(msg.sender, _amount);
    }

    function setStakeThreshold(
        uint256 _newThreshold,
        bytes calldata _signature
    ) external checkSubmitter {
        require(_newThreshold > 0, "Invalid Threshold");
        require(
            _verifySignature(
                keccak256(
                    abi.encodePacked(_newThreshold, tssNonce++, block.chainid)
                ),
                _signature
            ),
            "Invalid Signer"
        );
        stakeThreshold = _newThreshold;
        emit StakeThresholdUpdated(_newThreshold);
    }

    /**
     * @dev Set new tssSigner address.
     * @param _newSigner The new tssSigner address.
     * @param _signature The signature for verification.
     */
    function setSignerAddress(
        address _newSigner,
        bytes calldata _signature
    ) external checkSubmitter {
        require(_newSigner != address(0), "Invalid Address");
        require(
            _verifySignature(
                keccak256(
                    abi.encodePacked(_newSigner, tssNonce++, block.chainid)
                ),
                _signature
            ),
            "Invalid Signer"
        );

        tssSigner = _newSigner;
        emit SetSigner(_newSigner);
    }

    /**
     * @notice Initiates an add/remove proposer action.
     * @dev Only callable by the owner. When `_proposer` is not currently a proposer,
     *      this requests an addition and emits `AddProposerRequested`.
     *      When `_proposer` is currently a proposer, this requests a removal and emits `RemoveProposerRequested`.
     *      For removals a cooldown measured in `txId` is enforced: `txId >= lastRemoveProposerTxId + PROPOSER_REMOVE_WINDOW`.
     *      The action is finalized by calling `proposerConfirm` with a valid TSS signature.
     * @param _proposer The address to add to or remove from the proposer set.
     *
     * Requirements:
     * - `pendingProposer` must be the sentinel address `address(1)` (no pending request).
     * - For removals, the cooldown window must have passed.
     */
    function proposerRequest(address _proposer) external onlyOwner {
        require(pendingProposer == address(1), "Pending Proposer Not Empty");
        if (isProposer[_proposer]) {
            // Request to remove an existing proposer; enforce cooldown window
            require(
                txId >= lastRemoveProposerTxId + PROPOSER_REMOVE_WINDOW,
                "Proposer remove window not passed"
            );
            emit RemoveProposerRequested(_proposer, block.timestamp);
        } else {
            // Request to add a new proposer
            emit AddProposerRequested(_proposer, block.timestamp);
        }
        pendingProposer = _proposer;
    }

    /**
     * @notice Confirms the pending proposer add/remove request.
     * @dev Verifies the TSS signature over `abi.encodePacked(_proposer, tssNonce++, block.chainid)`.
     *      If `_proposer` is not currently a proposer, it is added; otherwise it is removed.
     *      On successful execution, `pendingProposer` is reset to the sentinel `address(1)`.
     *      When removing, `lastRemoveProposerTxId` is updated to the current `txId`.
     * @param _proposer The address to add or remove.
     * @param _signature The TSS signature approving the operation.
     */
    function proposerConfirm(
        address _proposer,
        bytes calldata _signature
    ) external {
        require(pendingProposer == _proposer, "Pending Proposer Not Matched");
        require(
            _verifySignature(
                keccak256(
                    abi.encodePacked(_proposer, tssNonce++, block.chainid)
                ),
                _signature
            ),
            "Invalid Signer"
        );
        if (!isProposer[_proposer]) {
            // Add proposer
            proposers.push(_proposer);
            isProposer[_proposer] = true;
        } else {
            // Remove proposer
            isProposer[_proposer] = false;
            for (uint256 i; i < proposers.length; ++i) {
                if (proposers[i] == _proposer) {
                    proposers[i] = proposers[proposers.length - 1];
                    proposers.pop();
                    break;
                }
            }
            lastRemoveProposerTxId = txId;
        }
        pendingProposer = address(1);
        emit ProposerConfirmed(_proposer, block.timestamp);
    }

    /**
     * @dev Entry point for all task handlers
     * @param _targets The contract address to be called.
     * @param _calldata The calldata of the function to be called.
     * @param _signature The signature for verification.
     */
    function verifyAndCall(
        address[] calldata _targets,
        bytes[] calldata _calldata,
        bytes calldata _signature
    ) external checkSubmitter nonReentrant returns (bool[] memory res) {
        require(
            _targets.length == _calldata.length,
            "Targets and Calldata Length Mismatch"
        );
        require(
            _verifySignature(
                keccak256(
                    abi.encode(_targets, _calldata, tssNonce++, block.chainid)
                ),
                _signature
            ),
            "Invalid Signer"
        );
        res = new bool[](_targets.length);
        for (uint256 i = 0; i < _targets.length; ++i) {
            (res[i], ) = _targets[i].call(_calldata[i]);
        }
        return res;
    }

    /**
     * @dev Verify the hash message.
     * @param _hash The hashed message.
     * @param _signature The signature for verification.
     */
    function _verifySignature(
        bytes32 _hash,
        bytes calldata _signature
    ) internal view returns (bool) {
        bytes32 messageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", _hash)
        );
        (bytes32 r, bytes32 s, uint8 v) = _splitSignature(_signature);
        address recoverAddr = ecrecover(messageHash, v, r, s);
        return tssSigner == recoverAddr;
    }

    /**
     * @dev Pick a new random submiter from the proposer list.
     */
    function _rotateSubmitter() internal {
        lastSubmissionTime = block.timestamp;
        nextSubmitter = _getRandomProposer(nextSubmitter);
        ++txId;
        emit SubmitterChosen(nextSubmitter);
    }

    function _getRandomProposer(address _salt) internal view returns (address) {
        uint256 randomIndex = uint256(
            keccak256(
                abi.encodePacked(
                    block.prevrandao, // instead of difficulty in PoS
                    block.timestamp,
                    blockhash(block.number),
                    _salt
                )
            )
        ) % proposers.length;
        return proposers[randomIndex];
    }

    /**
     * @dev Get rsv from signature.
     */
    function _splitSignature(
        bytes memory sig
    ) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Invalid signature length");

        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        if (v < 27) {
            v += 27;
        }

        require(v == 27 || v == 28, "Invalid signature version");
    }
}
