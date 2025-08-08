// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

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
    ReentrancyGuardUpgradeable
{
    uint256 public constant FORCE_ROTATION_WINDOW = 1 minutes;
    uint256 public constant MIN_PARTICIPANT_COUNT = 3;
    address public immutable stakeToken;

    uint256 public lastSubmissionTime;
    uint256 public tssNonce;
    address public tssSigner;

    address[] public proposers;
    address public nextSubmitter;
    mapping(address => bool) public isProposer;

    uint256 public stakeThreshold;
    mapping(address => uint256) public stakedAmounts;

    modifier checkSubmitter() {
        require(
            msg.sender == nextSubmitter,
            IncorrectSubmitter(msg.sender, nextSubmitter)
        );
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
        address _tssSigner,
        address[] calldata _initialProposers
    ) public initializer {
        __ReentrancyGuard_init();

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

    function setProposers(
        address[] calldata _newProposers,
        bytes calldata _signature
    ) external checkSubmitter {
        require(
            _newProposers.length > MIN_PARTICIPANT_COUNT,
            "Not Enough Proposers"
        );
        require(
            _verifySignature(
                keccak256(
                    abi.encodePacked(_newProposers, tssNonce++, block.chainid)
                ),
                _signature
            ),
            "Invalid Signer"
        );
        // Reset existing proposers
        for (uint256 i; i < proposers.length; ++i) {
            isProposer[proposers[i]] = false;
        }
        // add new proposers
        proposers = _newProposers;
        for (uint256 i; i < _newProposers.length; ++i) {
            isProposer[_newProposers[i]] = true;
        }
        emit SetProposer(_newProposers);
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
     * @dev Pick new random submitter if the current submitter is inactive for too long.
     * @param _signature The signature for verification.
     */
    function chooseNewSubmitter(
        bytes calldata _signature
    ) external nonReentrant {
        require(isProposer[msg.sender], "Not Proposer");
        require(
            block.timestamp >= lastSubmissionTime + FORCE_ROTATION_WINDOW,
            RotationWindowNotPassed(
                block.timestamp,
                lastSubmissionTime + FORCE_ROTATION_WINDOW
            )
        );
        require(
            _verifySignature(
                keccak256(
                    abi.encodePacked(
                        "chooseNewSubmitter",
                        tssNonce++,
                        block.chainid
                    )
                ),
                _signature
            ),
            "Invalid Signer"
        );
        emit SubmitterRotationRequested(msg.sender, nextSubmitter);
        _rotateSubmitter();
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
