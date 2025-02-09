// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

interface IDogechain {
    struct SPVProof {
        bytes32 txHash; // little endian
        bytes32[] txMerkleProof;
        uint256 txIndex;
        bytes32[] blockMerkleProof;
        uint256 blockIndex;
        address destEvmAddress;
        uint256 amount; // use to bridge-in amount check
        BlockHeader blockHeader;
        bytes txBytes; // use to bridge-in tx data check
    }

    struct BlockHeader {
        uint32 version;
        bytes32 prevBlock; // little endian
        bytes32 merkleRoot; // little endian
        uint32 timestamp;
        uint32 bits;
        uint32 nonce;
    }

    struct Batch {
        uint256 startBlock;
        uint256 totalElements;
        bytes32 rootHash;
    }

    event BatchSubmitted(uint256 batchId, uint256 startBlock, uint256 totalElements, bytes32 rootHash);
    event AdminAdded(address indexed admin);
    event AdminRemoved(address indexed admin);

    function admins(address account) external view returns (bool);

    function validateTransaction(uint256 batchId, SPVProof memory proof) external view returns (bool);

    // function extractBridgeInTransaction(bytes memory txData) external pure returns (uint256, address, bytes20);

    function submitBatch(uint256 startBlock, uint256 totalElements, bytes32 rootHash) external;

    function getBatch(uint256 batchId) external view returns (Batch memory);

    function addAdmin(address admin) external;

    function removeAdmin(address admin) external;

    function computeBlockHeaderHash(BlockHeader memory header) external pure returns (bytes32);

    function computeMerkleRoot(bytes32[] memory hashes) external pure returns (bytes32);
}
