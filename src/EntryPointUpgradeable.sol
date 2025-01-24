// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

import {IEntryPoint} from "./interfaces/IEntryPoint.sol";

/**
 * @dev Manage all onchain information.
 */
contract EntryPointUpgradeable is IEntryPoint, Initializable, ReentrancyGuardUpgradeable {
    uint256 public constant FORCE_ROTATION_WINDOW = 1 minutes;
    uint256 public constant MIN_PARTICIPANT_COUNT = 3;

    uint256 public lastSubmissionTime;
    uint256 public tssNonce;
    address public tssSigner;

    address[] public participants;
    mapping(address => bool) public isParticipant;
    address public nextSubmitter;

    modifier onlyCurrentSubmitter() {
        require(msg.sender == nextSubmitter, IncorrectSubmitter(msg.sender, nextSubmitter));
        _;
        _rotateSubmitter();
    }

    /**
     * @dev Initializes the contract.
     * @param _tssSigner The address of tssSigner.
     */
    function initialize(address _tssSigner, address[] calldata _initialParticipants) public initializer {
        __ReentrancyGuard_init();

        require(_tssSigner != address(0), InvalidAddress());
        tssSigner = _tssSigner;
        lastSubmissionTime = block.timestamp;
        participants = _initialParticipants;
        for (uint256 i; i < _initialParticipants.length; ++i) {
            isParticipant[_initialParticipants[i]] = true;
        }
        nextSubmitter = _getRandomParticipant(nextSubmitter);
        emit SubmitterChosen(nextSubmitter);
    }

    function setParticipants(address[] calldata _newParticipants) external onlyCurrentSubmitter {
        require(_newParticipants.length > MIN_PARTICIPANT_COUNT, "Not Enough Participants");
        // Reset existing participants
        for (uint256 i; i < participants.length; ++i) {
            isParticipant[participants[i]] = false;
        }
        // add new participants
        participants = _newParticipants;
        for (uint256 i; i < _newParticipants.length; ++i) {
            isParticipant[_newParticipants[i]] = true;
        }
        emit SetParticipant(_newParticipants);
    }

    /**
     * @dev Set new tssSigner address.
     * @param _newSigner The new tssSigner address.
     * @param _signature The signature for verification.
     */
    function setSignerAddress(address _newSigner, bytes calldata _signature) external onlyCurrentSubmitter {
        require(_newSigner != address(0), InvalidAddress());
        require(
            _verifySignature(keccak256(abi.encodePacked(_newSigner, tssNonce++, block.chainid)), _signature),
            "Invalid Signer"
        );

        tssSigner = _newSigner;
        emit SetSigner(_newSigner);
    }

    /**
     * @dev Pick new random submitter if the current submitter is inactive for too long.
     * @param _signature The signature for verification.
     */
    function chooseNewSubmitter(uint256 _uncompletedTaskCount, bytes calldata _signature) external nonReentrant {
        require(isParticipant[msg.sender], "Not Participant");
        require(
            block.timestamp >= lastSubmissionTime + FORCE_ROTATION_WINDOW,
            RotationWindowNotPassed(block.timestamp, lastSubmissionTime + FORCE_ROTATION_WINDOW)
        );
        require(
            _verifySignature(keccak256(abi.encodePacked(_uncompletedTaskCount, tssNonce++, block.chainid)), _signature),
            "Invalid Signer"
        );
        emit SubmitterRotationRequested(msg.sender, nextSubmitter);
        _rotateSubmitter();
    }

    /**
     * @dev Entry point for all task handlers
     * @param _target The contract address to be called.
     * @param _calldata The calldata of the function to be called.
     * @param _signature The signature for verification.
     */
    function verifyAndCall(address _target, bytes calldata _calldata, bytes calldata _signature)
        external
        onlyCurrentSubmitter
        nonReentrant
    {
        require(
            _verifySignature(keccak256(abi.encode(_calldata, tssNonce++, block.chainid)), _signature), "Invalid Signer"
        );
        (bool success,) = _target.call(_calldata);
        require(success, "Call Failed");
    }

    /**
     * @dev Verify the hash message.
     * @param _hash The hashed message.
     * @param _signature The signature for verification.
     */
    function _verifySignature(bytes32 _hash, bytes calldata _signature) internal view returns (bool) {
        bytes32 messageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _hash));
        (bytes32 r, bytes32 s, uint8 v) = _splitSignature(_signature);
        address recoverAddr = ecrecover(messageHash, v, r, s);
        return tssSigner == recoverAddr;
    }

    /**
     * @dev Pick a new random submiter from the participant list.
     */
    function _rotateSubmitter() internal {
        lastSubmissionTime = block.timestamp;
        nextSubmitter = _getRandomParticipant(nextSubmitter);
        emit SubmitterChosen(nextSubmitter);
    }

    function _getRandomParticipant(address _salt) internal view returns (address) {
        uint256 randomIndex = uint256(
            keccak256(
                abi.encodePacked(
                    block.prevrandao, // instead of difficulty in PoS
                    block.timestamp,
                    blockhash(block.number),
                    _salt
                )
            )
        ) % participants.length;
        return participants[randomIndex];
    }

    /**
     * @dev Get rsv from signature.
     */
    function _splitSignature(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
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
