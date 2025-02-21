// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {DogecoinBridge} from "../src/DogecoinBridge.sol";
import {Dogechain} from "../src/Dogechain.sol";
import {DogeToken} from "../src/DogeToken.sol";
import {DogeTransactionParser} from "../src/libraries/DogeTransactionParser.sol";

contract DogecoinBridgeScript is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        // Deploy DogeToken
        DogeToken dogeToken = new DogeToken();
        dogeToken.initialize();

        // Deploy Dogechain
        Dogechain dogechain = new Dogechain();
        dogechain.initialize();

        // Deploy DogecoinBridge
        DogecoinBridge bridge = new DogecoinBridge();
        bridge.initialize(
            address(dogeToken),
            address(dogechain),
            10,
            bytes20(0),
            bytes4(0x47514556),
            DogeTransactionParser.Network.MAINNET
        ); // Fee rate: 0.1%

        // Configure DogeToken bridge address
        dogeToken.setBridge(address(bridge));

        console.log("DogeToken deployed at:", address(dogeToken));
        console.log("Dogechain deployed at:", address(dogechain));
        console.log("DogecoinBridge deployed at:", address(bridge));

        vm.stopBroadcast();
    }
}
