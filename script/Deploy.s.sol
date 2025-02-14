// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {DogecoinBridge} from "../src/DogecoinBridge.sol";
import {Dogechain} from "../src/Dogechain.sol";
import {DogeToken} from "../src/DogeToken.sol";
import {EntryPointUpgradeable} from "../src/EntryPointUpgradeable.sol";

contract DogecoinBridgeScript is Script {
    function setUp() public {}

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        // Deploy EntryPoint
        EntryPointUpgradeable entryPoint = EntryPointUpgradeable(
            vm.envAddress("ENTRY_POINT")
        );
        // Note: EntryPoint is left un-initialized

        // Deploy DogeToken
        DogeToken dogeToken = new DogeToken();
        dogeToken.initialize();

        // Deploy Dogechain
        Dogechain dogechain = new Dogechain();
        dogechain.initialize(address(entryPoint));

        // Deploy DogecoinBridge
        DogecoinBridge bridge = new DogecoinBridge();
        bridge.initialize(
            address(entryPoint),
            address(dogeToken),
            address(dogechain),
            10,
            bytes20(0)
        ); // Fee rate: 0.1%

        // Configure DogeToken bridge address
        dogeToken.setBridge(address(bridge));

        console.log("EntryPoint deployed at:", address(entryPoint));
        console.log("DogeToken deployed at:", address(dogeToken));
        console.log("Dogechain deployed at:", address(dogechain));
        console.log("DogecoinBridge deployed at:", address(bridge));

        vm.stopBroadcast();
    }
}
