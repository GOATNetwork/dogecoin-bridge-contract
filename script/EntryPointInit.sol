// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {EntryPointUpgradeable} from "../src/EntryPointUpgradeable.sol";

contract DogecoinBridgeScript is Script {
    address entryPoint;
    address tssSigner;
    address[] proposers;

    function setUp() public {
        entryPoint = vm.envAddress("ENTRY_POINT");
        tssSigner = vm.envAddress("TSS_SIGNER");
        proposers.push(vm.envAddress("PROPOSER_1"));
        proposers.push(vm.envAddress("PROPOSER_2"));
        proposers.push(vm.envAddress("PROPOSER_3"));
    }

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        EntryPointUpgradeable entryPointContract = EntryPointUpgradeable(
            entryPoint
        );
        entryPointContract.initialize(tssSigner, proposers);

        vm.stopBroadcast();
    }
}
