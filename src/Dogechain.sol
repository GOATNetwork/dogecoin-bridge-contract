// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./interfaces/IDogechain.sol";
import "./libraries/BTCStyleMerkle.sol";

contract Dogechain is IDogechain, UUPSUpgradeable, OwnableUpgradeable {
    mapping(uint256 => Batch) public batches;
    uint256 public latestBatchId;

    mapping(address => bool) public admins;

    function initialize() external initializer {
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
        admins[msg.sender] = true;
        emit AdminAdded(msg.sender);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    modifier onlyAdmin() {
        require(admins[msg.sender], "Caller is not an admin");
        _;
    }

    function addAdmin(address admin) external override onlyOwner {
        require(admin != address(0), "Invalid admin address");
        require(!admins[admin], "Address is already an admin");
        admins[admin] = true;
        emit AdminAdded(admin);
    }

    function removeAdmin(address admin) external override onlyOwner {
        require(admins[admin], "Address is not an admin");
        admins[admin] = false;
        emit AdminRemoved(admin);
    }

    function submitBatch(uint256 startBlock, uint256 totalElements, bytes32 rootHash) external override onlyAdmin {
        if (latestBatchId > 0) {
            Batch memory previousBatch = batches[latestBatchId - 1];
            require(startBlock == previousBatch.startBlock + previousBatch.totalElements, "Invalid startBlock");
        }

        require(startBlock > 0, "Start block must be greater than 0");
        require(totalElements > 0 && totalElements <= 720, "Total elements must be greater than 0 and less than 720");
        require(rootHash != bytes32(0), "Root hash cannot be empty");

        batches[latestBatchId] = Batch({startBlock: startBlock, totalElements: totalElements, rootHash: rootHash});

        emit BatchSubmitted(latestBatchId, startBlock, totalElements, rootHash);
        latestBatchId++;
    }

    function getBatch(uint256 batchId) external view override returns (Batch memory) {
        return batches[batchId];
    }

    function validateTransaction(uint256 batchId, SPVProof memory proof) public view override returns (bool) {
        Batch memory batch = batches[batchId];
        require(batch.rootHash != bytes32(0), "Batch does not exist");

        require(
            BTCStyleMerkle.verifyMerkleProof(
                batch.rootHash, proof.blockMerkleProof, computeBlockHeaderHash(proof.blockHeader), proof.blockIndex
            ),
            "Invalid block proof"
        );

        require(
            BTCStyleMerkle.verifyMerkleProof(
                proof.blockHeader.merkleRoot, proof.txMerkleProof, proof.txHash, proof.txIndex
            ),
            "Invalid transaction proof"
        );

        return true;
    }

    function extractAmount(bytes memory txData) external pure override returns (uint256) {
        // Mock implementation
        return abi.decode(txData, (uint256));
    }

    /**
     * @dev compute block header hash
     * @param header BlockHeader
     * @return bytes32 block header hash in little endian
     */
    function computeBlockHeaderHash(BlockHeader memory header) public pure returns (bytes32) {
        // Pack the header fields in little-endian
        bytes memory packed = abi.encodePacked(
            BTCStyleMerkle.reverseBytes4(header.version),
            header.prevBlock, // little endian input, not reversed
            header.merkleRoot, // little endian input, not reversed
            BTCStyleMerkle.reverseBytes4(header.timestamp),
            BTCStyleMerkle.reverseBytes4(header.bits),
            BTCStyleMerkle.reverseBytes4(header.nonce)
        );

        // Double SHA256 hash
        return BTCStyleMerkle.doubleSha256Bytes(packed);
    }

    /**
     * @dev Computes the Merkle Root from a list of transaction hashes.
     * @param hashes Array of transaction hashes (32-byte each).
     * @return merkleRoot The computed Merkle Root.
     */
    function computeMerkleRoot(bytes32[] memory hashes) public pure returns (bytes32) {
        return BTCStyleMerkle.computeMerkleRoot(hashes);
    }
}
