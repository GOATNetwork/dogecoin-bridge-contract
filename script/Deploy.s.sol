// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {DogecoinBridge} from "../src/DogecoinBridge.sol";
import {Dogechain} from "../src/Dogechain.sol";
import {DogeToken} from "../src/DogeToken.sol";
import {EntryPointUpgradeable} from "../src/EntryPointUpgradeable.sol";
import {DogeTransactionParser} from "../src/libraries/DogeTransactionParser.sol";

contract DogecoinBridgeScript is Script {
    address tokenAddress;

    function setUp() public {}

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        tokenAddress = vm.envAddress("TOKEN_ADDRESS");

        vm.startBroadcast(deployerPrivateKey);

        deployLogic();

        vm.stopBroadcast();
    }

    function deploy() public {
        // Deploy EntryPoint
        EntryPointUpgradeable entryPoint = new EntryPointUpgradeable(
            tokenAddress
        );
        // Note: EntryPoint is left un-initialized

        // Deploy DogeToken
        DogeToken dogeToken = new DogeToken();

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
            bytes20(0),
            bytes4(0x47514556),
            DogeTransactionParser.Network.MAINNET
        ); // Fee rate: 0.1%

        // Configure DogeToken bridge address
        dogeToken.setBridge(address(bridge));

        console.log("EntryPoint deployed at:", address(entryPoint));
        console.log("DogeToken deployed at:", address(dogeToken));
        console.log("Dogechain deployed at:", address(dogechain));
        console.log("DogecoinBridge deployed at:", address(bridge));
    }

    function deployLogic() public {
        // Deploy EntryPoint
        EntryPointUpgradeable entryPoint = new EntryPointUpgradeable(
            tokenAddress
        );
        // Deploy DogecoinBridge
        DogecoinBridge bridge = new DogecoinBridge();

        console.log("EntryPoint deployed at:", address(entryPoint));
        console.log("DogecoinBridge deployed at:", address(bridge));
    }
}
