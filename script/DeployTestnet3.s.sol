// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {DogecoinBridge} from "../src/DogecoinBridge.sol";
import {Dogechain} from "../src/Dogechain.sol";
import {DogeToken} from "../src/DogeToken.sol";
import {EntryPointUpgradeable} from "../src/EntryPointUpgradeable.sol";
import {DogeTransactionParser} from "../src/libraries/DogeTransactionParser.sol";

contract DeployTestnet3Script is Script {
    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        // Deploy DogeToken
        DogeToken dogeToken = new DogeToken();
        console.log("DogeToken deployed at:", address(dogeToken));

        // Deploy EntryPoint (uses DogeToken as stakeToken)
        EntryPointUpgradeable entryPoint = new EntryPointUpgradeable(
            address(dogeToken)
        );
        console.log("EntryPoint deployed at:", address(entryPoint));

        // Initialize EntryPoint with TSS_SIGNER and PROPOSERS
        address[] memory proposers = new address[](3);
        proposers[0] = 0xE07dc2f6112E5B38237cb9620eA0075eF25e5E79; // PROPOSER_1
        proposers[1] = 0x4E6588f5eb6D328ABB46df71C74D7031cC962C85; // PROPOSER_2
        proposers[2] = 0xe0a189c72078AB9A4B0ebfcd3eEf46153392a152; // PROPOSER_3

        entryPoint.initialize(
            0x80BCcc69E2DCdf75E30132082Cb00B21f5EbF00b, // owner
            0x927C6216357888B6cbd46758dCcdbb9F25D0d639, // TSS_SIGNER
            proposers
        );
        console.log("EntryPoint initialized");

        // Deploy Dogechain
        Dogechain dogechain = new Dogechain();
        dogechain.initialize(address(entryPoint));
        console.log("Dogechain deployed at:", address(dogechain));

        // Deploy DogecoinBridge
        DogecoinBridge bridge = new DogecoinBridge();
        bridge.initialize(
            address(entryPoint),
            address(dogeToken),
            address(dogechain),
            0, // Fee rate: 0% (free)
            bytes20(0xFc456386689dfe8e94dfcfAe8A0b953eB91d140b), // _dogecoinBridgePK
            bytes4(0x47514556), // _opReturnMagicPrefix (GQEV)
            DogeTransactionParser.Network.TESTNET
        );
        console.log("DogecoinBridge deployed at:", address(bridge));

        // Configure DogeToken bridge address
        dogeToken.setBridge(address(bridge));
        console.log("DogeToken bridge configured");

        vm.stopBroadcast();

        console.log("");
        console.log("=== DEPLOYMENT SUMMARY ===");
        console.log("DogeToken:", address(dogeToken));
        console.log("EntryPoint:", address(entryPoint));
        console.log("Dogechain:", address(dogechain));
        console.log("DogecoinBridge:", address(bridge));
    }
}
