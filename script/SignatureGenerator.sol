// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Script, console} from "forge-std/Script.sol";

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {IDogechain} from "../src/interfaces/IDogechain.sol";
import {DogecoinBridge} from "../src/DogecoinBridge.sol";
import {EntryPointUpgradeable} from "../src/EntryPointUpgradeable.sol";

contract SignatureGenerator is Script {
    using MessageHashUtils for bytes32;
    using ECDSA for bytes32;

    uint256 privKey;

    EntryPointUpgradeable entryPoint;

    function setUp() public {
        privKey = vm.envUint("PRIVATE_KEY");
        entryPoint = EntryPointUpgradeable(vm.envAddress("ENTRY_POINT"));
    }

    function run() public {
        submitBatch(1, 2, bytes32(uint256(1234)));
    }

    // forge script --rpc-url localhost script/SignatureGenerator.sol --sig "submitBatch(uint256,uint256,bytes32)"
    function submitBatch(
        uint256 startBlock,
        uint256 totalElements,
        bytes32 rootHash
    ) public view returns (bytes memory) {
        bytes memory callData = abi.encodeWithSelector(
            IDogechain.submitBatch.selector,
            startBlock,
            totalElements,
            rootHash
        );
        return _generateSig(callData);
    }

    function bridgeIn(
        IDogechain.SPVProof[] memory proofs,
        uint256 batchId
    ) public view returns (bytes memory) {
        bytes memory callData = abi.encodeWithSelector(
            DogecoinBridge.bridgeIn.selector,
            proofs,
            batchId
        );
        return _generateSig(callData);
    }

    function bridgeOutFinish(
        uint256 batchId,
        IDogechain.SPVProof memory proof,
        uint256[] memory taskIds
    ) public view returns (bytes memory) {
        bytes memory callData = abi.encodeWithSelector(
            DogecoinBridge.bridgeOutFinish.selector,
            batchId,
            proof,
            taskIds
        );
        return _generateSig(callData);
    }

    function _generateSig(
        bytes memory _calldata
    ) internal view returns (bytes memory) {
        bytes32 messageHash = keccak256(
            abi.encodePacked(_calldata, entryPoint.tssNonce(), block.chainid)
        ).toEthSignedMessageHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, messageHash);
        console.logBytes(abi.encodePacked(r, s, v));
        return abi.encodePacked(r, s, v);
    }
}
