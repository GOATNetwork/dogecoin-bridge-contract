// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./interfaces/IDogechain.sol";
import "./libraries/BTCStyleMerkle.sol";

contract Dogechain is IDogechain, UUPSUpgradeable, OwnableUpgradeable {
    mapping(uint256 => Batch) public batches;
    uint256 public latestBatchId;

    function initialize(address _entryPoint) external initializer {
        __Ownable_init(_entryPoint);
        __UUPSUpgradeable_init();
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {}

    function submitBatch(
        uint256 startBlock,
        uint256 totalElements,
        bytes32 rootHash
    ) external override onlyOwner {
        if (latestBatchId > 0) {
            Batch memory previousBatch = batches[latestBatchId - 1];
            require(
                startBlock ==
                    previousBatch.startBlock + previousBatch.totalElements,
                "Invalid startBlock"
            );
        }

        require(startBlock > 0, "Start block must be greater than 0");
        require(
            totalElements > 0 && totalElements <= 720,
            "Total elements must be greater than 0 and less than 720"
        );
        require(rootHash != bytes32(0), "Root hash cannot be empty");

        batches[latestBatchId] = Batch({
            startBlock: startBlock,
            totalElements: totalElements,
            rootHash: rootHash
        });

        emit BatchSubmitted(latestBatchId, startBlock, totalElements, rootHash);
        latestBatchId++;
    }

    function getBatch(
        uint256 batchId
    ) external view override returns (Batch memory) {
        return batches[batchId];
    }

    function validateTransaction(
        uint256 batchId,
        bytes32 txid,
        SPVProof memory proof
    ) public view override returns (bool) {
        Batch memory batch = batches[batchId];
        require(batch.rootHash != bytes32(0), "Batch does not exist");

        require(
            BTCStyleMerkle.verifyMerkleProof(
                proof.blockHeader.merkleRoot,
                proof.txMerkleProof,
                txid,
                proof.txIndex
            ),
            "Invalid transaction proof"
        );

        require(
            BTCStyleMerkle.verifyMerkleProof(
                batch.rootHash,
                proof.blockMerkleProof,
                computeBlockHeaderHash(proof.blockHeader),
                proof.blockIndex
            ),
            "Invalid block proof"
        );

        return true;
    }

    // function extractBridgeInTransaction(bytes memory txData) external pure override returns (uint256, address, bytes20) {
    //     // TODO: dogecoin tx data parse implementation
    //     // dogecoin 8 decimal to 18 decimal here
    //     return (0, address(0), bytes20(0));
    // }

    /**
     * @dev compute block header hash
     * @param header BlockHeader
     * @return bytes32 block header hash in little endian
     */
    function computeBlockHeaderHash(
        BlockHeader memory header
    ) public pure returns (bytes32) {
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
    function computeMerkleRoot(
        bytes32[] memory hashes
    ) public pure returns (bytes32) {
        return BTCStyleMerkle.computeMerkleRoot(hashes);
    }
}
