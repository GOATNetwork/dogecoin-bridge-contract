// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {Dogechain} from "../src/Dogechain.sol";
import {DogeToken} from "../src/DogeToken.sol";
import {IDogechain} from "../src/interfaces/IDogechain.sol";
import {DogecoinBridge} from "../src/DogecoinBridge.sol";
import {EntryPointUpgradeable, IEntryPoint} from "../src/EntryPointUpgradeable.sol";
import {BTCStyleMerkle} from "../src/libraries/BTCStyleMerkle.sol";
import {DogeTransactionParser} from "../src/libraries/DogeTransactionParser.sol";

import {MockToken} from "../src/mocks/MockToken.sol";

contract DogecoinBridgeTest is Test {
    using MessageHashUtils for bytes32;

    DogeToken public dogeToken;
    Dogechain public dogechain;
    DogecoinBridge public bridge;
    EntryPointUpgradeable public entryPoint;

    address public owner = address(1);
    address public proposer = address(2);
    address public user = address(3);
    address public tssSigner;

    uint256 public tssKey;

    function setUp() public {
        (tssSigner, tssKey) = makeAddrAndKey("tss");

        // Deploy and initialize contracts
        MockToken mockToken = new MockToken();

        vm.startPrank(owner);
        entryPoint = new EntryPointUpgradeable(address(mockToken));
        address[] memory proposers = new address[](1);
        proposers[0] = proposer;
        entryPoint.initialize(tssSigner, proposers);

        dogeToken = new DogeToken();

        dogechain = new Dogechain();
        dogechain.initialize(address(entryPoint));

        bridge = new DogecoinBridge();
        bridge.initialize(
            address(entryPoint),
            address(dogeToken),
            address(dogechain),
            10,
            hex"059ce0647de86cf966dfa4656a08530eb8f26772",
            bytes4("GTV1"),
            DogeTransactionParser.Network.MAINNET
        ); // Fee rate: 0.1%

        // Set bridge address in DogeToken
        dogeToken.setBridge(address(bridge));

        vm.stopPrank();
    }

    function testInitializeContracts() public view {
        assertEq(dogeToken.bridge(), address(bridge));
    }

    function testComputeDogechainBlockMerkleRoot() public pure {
        // dogechain block 5556718
        // See ../dogeblocks-demo.json & https://dogechain.info/block/5556718
        bytes32[] memory txHashes = new bytes32[](5);
        txHashes[0] = BTCStyleMerkle.reverseBytes32(
            0x6f35b9e9cff6e788b6fb9e4a707a972081fe3a28369bca9e4319b10a4751e68f
        );
        txHashes[1] = BTCStyleMerkle.reverseBytes32(
            0x459d296c42514f5afc51473766733c7d5a5250035eeeaaee827dd603a8cc7ecf
        );
        txHashes[2] = BTCStyleMerkle.reverseBytes32(
            0x6bbd9c94b705c84cb268b653c942d968e2a55ce761886f6b70de296d008e975f
        );
        txHashes[3] = BTCStyleMerkle.reverseBytes32(
            0x9033cc33e386b433d60099da2b24b12c15dcfeed35729740b761b0bbcdd884ca
        );
        txHashes[4] = BTCStyleMerkle.reverseBytes32(
            0xc9f32925b55fa915023a02ab6967765a665493b0b13fc33209a60312500d019a
        );

        bytes32 root = BTCStyleMerkle.computeMerkleRoot(txHashes);
        assertEq(
            root,
            BTCStyleMerkle.reverseBytes32(
                0xa2f10e9e2dc6dede16d9775395dc015572c4e3a128e6aebe7bc9780f754d296a
            )
        );
    }

    function testComputeDogechainBlockHash() public view {
        // dogechain block 5556718
        // See ../dogeblocks-demo.json & https://dogechain.info/block/5556718
        IDogechain.BlockHeader memory header = IDogechain.BlockHeader({
            version: 6422788,
            prevBlock: BTCStyleMerkle.reverseBytes32(
                0x0bbfc4b2d3b8e4e3e66d3a4dae6338c0d7a9ae26040575be1f15254ad602d40c
            ),
            merkleRoot: BTCStyleMerkle.reverseBytes32(
                0xa2f10e9e2dc6dede16d9775395dc015572c4e3a128e6aebe7bc9780f754d296a
            ),
            timestamp: 1737618144,
            bits: 0x197c63d0,
            nonce: 0x0000000000000000000000000000000000000000000000000000000000000000
        });
        bytes32 hash = dogechain.computeBlockHeaderHash(header);
        assertEq(
            hash,
            BTCStyleMerkle.reverseBytes32(
                0xfb4cc1df87acfe4bd5998d885c664edcd949ac8d2f24affa9a2bfe9f7d3945a5
            )
        );
    }

    function testGetTxid() public pure {
        bytes
            memory txData = hex"0200000001bb6b4a499069ba4094d04f41a5bbaa8861838deff0a2f484da7469f6ed98a8ff000000006a47304402201ce3feea47bd407c3f24474f0e25cfd42bfc4b10f33443536da2d72c5fd4dc0a02201c583e8fc190bd7beb157fcb7ab46ca82fef10bbc5060ecfc57f760e26170d7a01210361e82e71277ea205814b1cb69777abe5fc417c03d4d39829cefb8f92da08b1fcffffffff02605af405000000001976a914059ce0647de86cf966dfa4656a08530eb8f2677288ac00000000000000001a6a18475456319e2516fffaaf9a3fb7d92868fa2d4bc452163a1400000000";
        bytes32 txid = DogeTransactionParser.getTxid(txData);
        assertEq(
            txid,
            BTCStyleMerkle.reverseBytes32(
                0x87255de9393c93ded6b5d659f6761c2b8f7c0467789ff2f41e129d1f569a583b
            )
        );
    }

    function testParseBridgeInP2PKHTxOfRegtest() public pure {
        bytes
            memory txData = hex"0200000001bb6b4a499069ba4094d04f41a5bbaa8861838deff0a2f484da7469f6ed98a8ff000000006a47304402201ce3feea47bd407c3f24474f0e25cfd42bfc4b10f33443536da2d72c5fd4dc0a02201c583e8fc190bd7beb157fcb7ab46ca82fef10bbc5060ecfc57f760e26170d7a01210361e82e71277ea205814b1cb69777abe5fc417c03d4d39829cefb8f92da08b1fcffffffff02605af405000000001976a914059ce0647de86cf966dfa4656a08530eb8f2677288ac00000000000000001a6a18475456319e2516fffaaf9a3fb7d92868fa2d4bc452163a1400000000";
        (
            DogeTransactionParser.P2PKHOutput memory p2pkhOutput,
            bytes memory opReturnData,
            bool isP2PKHWithOpReturn
        ) = DogeTransactionParser.parseBridgeInP2PKHTransaction(txData);
        string memory expectedAddress = DogeTransactionParser.encodeBase58(
            DogeTransactionParser.getDogecoinAddress(
                p2pkhOutput.publicKeyHash,
                DogeTransactionParser.Network.REGTEST,
                0
            )
        );
        string memory actualAddress = "mg2dbz8VTPUiNWa5uA1QNqYAsR2hcChq4i";
        assertTrue(isP2PKHWithOpReturn);
        assertEq(p2pkhOutput.value, 99900000);
        assertEq(bytes(expectedAddress).length, bytes(actualAddress).length);
        assertEq(expectedAddress, actualAddress);
        assertTrue(opReturnData.length == 24);
        bytes4 magicPrefix = bytes4(opReturnData);
        assertEq(magicPrefix, bytes4("GTV1"));
        bytes memory slicedData = new bytes(20);
        for (uint256 i = 4; i < 24; i++) {
            slicedData[i - 4] = opReturnData[i];
        }
        address destAddress = address(uint160(bytes20(slicedData)));
        assertEq(
            destAddress,
            address(
                uint160(bytes20(hex"9e2516fffaaf9a3fb7d92868fa2d4bc452163a14"))
            )
        );
    }

    function testParseBridgeOutP2PKHTxOfRegtest() public pure {
        bytes
            memory txData = hex"0200000001bb6b4a499069ba4094d04f41a5bbaa8861838deff0a2f484da7469f6ed98a8ff000000006a47304402201ce3feea47bd407c3f24474f0e25cfd42bfc4b10f33443536da2d72c5fd4dc0a02201c583e8fc190bd7beb157fcb7ab46ca82fef10bbc5060ecfc57f760e26170d7a01210361e82e71277ea205814b1cb69777abe5fc417c03d4d39829cefb8f92da08b1fcffffffff02605af405000000001976a914059ce0647de86cf966dfa4656a08530eb8f2677288ac00000000000000001a6a18475456319e2516fffaaf9a3fb7d92868fa2d4bc452163a1400000000";
        (
            DogeTransactionParser.P2PKHOutput[] memory allOutputs,
            uint8 p2pkhOutputCount
        ) = DogeTransactionParser.parseBridgeOutP2PKHTransaction(txData);
        assertEq(allOutputs.length, 2);
        assertEq(p2pkhOutputCount, 1);
        assertEq(allOutputs[0].value, 99900000);
        string memory expectedAddress = DogeTransactionParser.encodeBase58(
            DogeTransactionParser.getDogecoinAddress(
                allOutputs[0].publicKeyHash,
                DogeTransactionParser.Network.REGTEST,
                0
            )
        );
        string memory actualAddress = "mg2dbz8VTPUiNWa5uA1QNqYAsR2hcChq4i";
        assertEq(bytes(expectedAddress).length, bytes(actualAddress).length);
        assertEq(expectedAddress, actualAddress);
    }

    function testParseBridgeOutP2PKHTxOfMainnet() public pure {
        bytes
            memory txData = hex"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3503eec9540fe4b883e5bda9e7a59ee4bb99e9b1bc205b323032352d30312d32335430373a34323a32342e3534373132313330355a5dffffffff01a01305efe80000001976a91447b6ccaa4525a3e9a2806d7aeadc978b4933553788ac00000000";
        (
            DogeTransactionParser.P2PKHOutput[] memory allOutputs,
            uint8 p2pkhOutputCount
        ) = DogeTransactionParser.parseBridgeOutP2PKHTransaction(txData);
        assertEq(allOutputs.length, 1);
        assertEq(p2pkhOutputCount, 1);
        assertEq(allOutputs[0].value, 1000442500000);
        string memory expectedAddress = DogeTransactionParser.encodeBase58(
            DogeTransactionParser.getDogecoinAddress(
                allOutputs[0].publicKeyHash,
                DogeTransactionParser.Network.MAINNET,
                0
            )
        );
        string memory actualAddress = "DBgHW1Shjyk91fusm9hm3HcryNBwaFwZbQ";
        assertEq(bytes(expectedAddress).length, bytes(actualAddress).length);
        assertEq(expectedAddress, actualAddress);
    }

    /**
     * @notice This test is not working, because the block hash is not correct
     */
    function testBridgeIn() public {
        vm.startPrank(address(entryPoint));
        dogechain.submitBatch(100, 3, bytes32(uint256(1))); // Dummy batch for testing

        // this needs to extract from the OP_RETURN data at client side, contract side will verify it
        address destAddress = address(
            uint160(bytes20(hex"9e2516fffaaf9a3fb7d92868fa2d4bc452163a14"))
        );

        IDogechain.BridgeTransaction[] memory bridgeTxs = new IDogechain.BridgeTransaction[](1);
        bridgeTxs[0] = IDogechain.BridgeTransaction({
            destEvmAddress: destAddress,
            amount: 99900000,
            txBytes: hex"02000000011615c449a5b2f572e5c3693e89c9c4be0bf021a68c68359b725537aa58376a7a010000006b4830450221009d46ea44468ca4600219d4e0dc949e14d92740bb3efeed5dad42d45c9a78ae6d02201bfc5d1f7b2b111ef5d022fc6c4e3b6a3f5ed296d23e3081595e50d6e8dd52e501210361e82e71277ea205814b1cb69777abe5fc417c03d4d39829cefb8f92da08b1fcffffffff02605af405000000001976a914059ce0647de86cf966dfa4656a08530eb8f2677288ac00000000000000001a6a18475456319e2516fffaaf9a3fb7d92868fa2d4bc452163a1400000000"
        });

        // Bridge in tokens
        bridge.bridgeIn(bridgeTxs, 0);

        assertEq(dogeToken.balanceOf(destAddress), 99900000);
        vm.stopPrank();
    }

    function testBridgeOut() public {
        vm.startPrank(address(bridge));
        // Mint tokens for user
        dogeToken.mint(user, 1000);
        vm.stopPrank();

        vm.startPrank(user);
        // Approve tokens for bridge
        dogeToken.approve(address(bridge), 1000);

        // Bridge out tokens
        bridge.bridgeOut(500, "destination-address");

        assertEq(dogeToken.balanceOf(user), 500); // Remaining balance
        assertEq(dogeToken.balanceOf(address(bridge)), 500); // Bridge balance
        vm.stopPrank();
    }

    function testBridgeOutFinish() public {
        vm.startPrank(address(entryPoint));
        dogechain.submitBatch(100, 3, bytes32(uint256(1))); // Dummy batch for testing
        vm.stopPrank();

        // Add bridge out task
        vm.startPrank(address(bridge));
        dogeToken.mint(user, 1000);
        vm.stopPrank();

        vm.startPrank(user);
        dogeToken.approve(address(bridge), 1000);
        bridge.bridgeOut(500, bytes20("destination-address"));
        vm.stopPrank();

        vm.startPrank(address(entryPoint));
        // Complete the bridge out by proposer
        IDogechain.BridgeTransaction memory bridgeTx = IDogechain.BridgeTransaction({
            destEvmAddress: address(proposer),
            amount: 100,
            txBytes: hex"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3503eec9540fe4b883e5bda9e7a59ee4bb99e9b1bc205b323032352d30312d32335430373a34323a32342e3534373132313330355a5dffffffff01a01305efe80000001976a91447b6ccaa4525a3e9a2806d7aeadc978b4933553788ac00000000"
        });

        uint256[] memory taskIds = new uint256[](1);
        taskIds[0] = 0;

        bridge.bridgeOutFinish(0, bridgeTx, taskIds);
        (
            address from,
            uint256 destAmount,
            bytes20 destDogecoinAddress,
            uint8 status
        ) = bridge.bridgeOutTasks(0);
        assertEq(status, 5);
        assertEq(from, user);
        assertEq(destAmount, 500);
        assertEq(destDogecoinAddress, bytes20("destination-address"));
        assertEq(dogeToken.balanceOf(address(bridge)), 0); // Tokens burned
        vm.stopPrank();
    }

    function testCallFromEntryPoint() public {
        bytes32[] memory blockHashes = new bytes32[](3);
        blockHashes[0] = BTCStyleMerkle.reverseBytes32(
            0x0bbfc4b2d3b8e4e3e66d3a4dae6338c0d7a9ae26040575be1f15254ad602d40c
        );
        blockHashes[1] = BTCStyleMerkle.reverseBytes32(
            0xfb4cc1df87acfe4bd5998d885c664edcd949ac8d2f24affa9a2bfe9f7d3945a5
        );
        blockHashes[2] = BTCStyleMerkle.reverseBytes32(
            0x71d6f54a64ffa8f148a0b2449ccefa5d76637e943d2fd898364ef4b414a19a58
        );
        (, bytes32 blockHashMerkleRoot) = BTCStyleMerkle.generateMerkleProof(
            blockHashes,
            1
        );

        bytes32 computedRoot = BTCStyleMerkle.computeMerkleRoot(blockHashes);
        assertEq(computedRoot, blockHashMerkleRoot);

        address[] memory targets = new address[](1);
        targets[0] = address(dogechain);
        bytes[] memory callDatas = new bytes[](1);
        callDatas[0] = abi.encodeWithSelector(
            dogechain.submitBatch.selector,
            5556717,
            3,
            blockHashMerkleRoot
        );
        bytes memory encodedData = abi.encode(
            targets,
            callDatas,
            entryPoint.tssNonce(),
            block.chainid
        );
        bytes32 digest = keccak256(encodedData).toEthSignedMessageHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Fail: not proposer
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.IncorrectSubmitter.selector,
                address(this),
                proposer
            )
        );
        entryPoint.verifyAndCall(targets, callDatas, signature);

        // Fail: incorrect signature
        vm.startPrank(proposer);
        vm.expectRevert("Invalid Signer");
        entryPoint.verifyAndCall(targets, callDatas, signature);

        // Success
        (v, r, s) = vm.sign(tssKey, digest);
        signature = abi.encodePacked(r, s, v);
        entryPoint.verifyAndCall(targets, callDatas, signature);
    }

    /**
     * @notice This test is not working, because the block hash is not correct
     */
    function testBridgeIn_Deprecated() public {
        vm.skip(true);
        vm.startPrank(address(entryPoint));

        bytes32[] memory blockHashes = new bytes32[](3);
        // block 125 in regtest
        blockHashes[0] = BTCStyleMerkle.reverseBytes32(
            0x841ca96a59778c0d30e9a1cb70cb3329402de0ae1633e7c029cdd9874280a12c
        );
        // 126
        blockHashes[1] = BTCStyleMerkle.reverseBytes32(
            0x7689cc2cf531ca0d04ed4bf94348f87650a4a3385b4ff82de35416a809154887
        );
        // 127
        blockHashes[2] = BTCStyleMerkle.reverseBytes32(
            0xf3feb36a650888afc7006dfee0e30516e1564e301d49f773b853b1930d27b5df
        );
        (
            bytes32[] memory blockMerkleProof,
            bytes32 blockHashMerkleRoot
        ) = BTCStyleMerkle.generateMerkleProof(blockHashes, 1);

        bytes32 computedRoot = BTCStyleMerkle.computeMerkleRoot(blockHashes);
        assertEq(computedRoot, blockHashMerkleRoot);

        // create a batch and SPV proof, submit it
        dogechain.submitBatch(125, 3, blockHashMerkleRoot);

        // block 126 txs in regtest
        bytes32[] memory txHashes = new bytes32[](2);
        txHashes[0] = BTCStyleMerkle.reverseBytes32(
            0x83f05c4d03c03acb6b97f87b226f0540db01636843beed8e52f5a9f124e9e5b4
        );
        txHashes[1] = BTCStyleMerkle.reverseBytes32(
            0x683f58fdfaf5558c43bd2f3d0c6716237e6d6f0e25eeadbf03ef4cc179e10fd1
        );
        // generate deposit TX merkle proof in a block
        (bytes32[] memory txMerkleProof, ) = BTCStyleMerkle.generateMerkleProof(
            txHashes,
            1
        );

        // this needs to extract from the OP_RETURN data at client side, contract side will verify it
        address destAddress = address(
            uint160(bytes20(hex"9e2516fffaaf9a3fb7d92868fa2d4bc452163a14"))
        );

        IDogechain.SPVProof[] memory proofs = new IDogechain.SPVProof[](1);
        proofs[0] = IDogechain.SPVProof({
            txMerkleProof: txMerkleProof,
            txIndex: 1,
            blockHeader: IDogechain.BlockHeader({
                version: 6422532,
                prevBlock: BTCStyleMerkle.reverseBytes32(
                    0x841ca96a59778c0d30e9a1cb70cb3329402de0ae1633e7c029cdd9874280a12c
                ),
                merkleRoot: BTCStyleMerkle.reverseBytes32(
                    0x0436c23211cbedc9c5b1cedccab9dbcfb2a965ad8b0cc93b06901188f20afa84
                ),
                timestamp: 1740295218,
                bits: 0x207fffff,
                nonce: 1
            }),
            blockMerkleProof: blockMerkleProof,
            blockIndex: 1,
            destEvmAddress: destAddress,
            amount: 99900000,
            txBytes: hex"02000000011615c449a5b2f572e5c3693e89c9c4be0bf021a68c68359b725537aa58376a7a010000006b4830450221009d46ea44468ca4600219d4e0dc949e14d92740bb3efeed5dad42d45c9a78ae6d02201bfc5d1f7b2b111ef5d022fc6c4e3b6a3f5ed296d23e3081595e50d6e8dd52e501210361e82e71277ea205814b1cb69777abe5fc417c03d4d39829cefb8f92da08b1fcffffffff02605af405000000001976a914059ce0647de86cf966dfa4656a08530eb8f2677288ac00000000000000001a6a18475456319e2516fffaaf9a3fb7d92868fa2d4bc452163a1400000000"
        });

        // verify the block proof at client side, before do bridge-in
        bool blockProofValidation = BTCStyleMerkle.verifyMerkleProof(
            blockHashMerkleRoot,
            blockMerkleProof,
            BTCStyleMerkle.reverseBytes32(
                0x7689cc2cf531ca0d04ed4bf94348f87650a4a3385b4ff82de35416a809154887
            ),
            1
        );
        assertTrue(blockProofValidation);

        // Bridge in tokens
        // bridge.bridgeIn(proofs, 0);

        assertEq(dogeToken.balanceOf(destAddress), 99900000);
        vm.stopPrank();
    }

    function testBridgeOutFinish_Deprecated() public {
        vm.skip(true);
        vm.startPrank(address(entryPoint));
        // Create a batch by proposer
        bytes32[] memory blockHashes = new bytes32[](3);
        blockHashes[0] = BTCStyleMerkle.reverseBytes32(
            0x0bbfc4b2d3b8e4e3e66d3a4dae6338c0d7a9ae26040575be1f15254ad602d40c
        );
        blockHashes[1] = BTCStyleMerkle.reverseBytes32(
            0xfb4cc1df87acfe4bd5998d885c664edcd949ac8d2f24affa9a2bfe9f7d3945a5
        );
        blockHashes[2] = BTCStyleMerkle.reverseBytes32(
            0x71d6f54a64ffa8f148a0b2449ccefa5d76637e943d2fd898364ef4b414a19a58
        );
        (
            bytes32[] memory blockMerkleProof,
            bytes32 blockHashMerkleRoot
        ) = BTCStyleMerkle.generateMerkleProof(blockHashes, 1);

        bytes32 computedRoot = BTCStyleMerkle.computeMerkleRoot(blockHashes);
        assertEq(computedRoot, blockHashMerkleRoot);

        // Create a batch and SPV proof
        dogechain.submitBatch(5556717, 3, blockHashMerkleRoot);

        vm.stopPrank();

        // Add bridge out task
        vm.startPrank(address(bridge));
        dogeToken.mint(user, 1000);
        vm.stopPrank();

        vm.startPrank(user);
        dogeToken.approve(address(bridge), 1000);
        bridge.bridgeOut(500, bytes20("destination-address"));
        vm.stopPrank();

        vm.startPrank(address(entryPoint));

        bytes32[] memory txHashes = new bytes32[](5);
        txHashes[0] = BTCStyleMerkle.reverseBytes32(
            0x6f35b9e9cff6e788b6fb9e4a707a972081fe3a28369bca9e4319b10a4751e68f
        );
        txHashes[1] = BTCStyleMerkle.reverseBytes32(
            0x459d296c42514f5afc51473766733c7d5a5250035eeeaaee827dd603a8cc7ecf
        );
        txHashes[2] = BTCStyleMerkle.reverseBytes32(
            0x6bbd9c94b705c84cb268b653c942d968e2a55ce761886f6b70de296d008e975f
        );
        txHashes[3] = BTCStyleMerkle.reverseBytes32(
            0x9033cc33e386b433d60099da2b24b12c15dcfeed35729740b761b0bbcdd884ca
        );
        txHashes[4] = BTCStyleMerkle.reverseBytes32(
            0xc9f32925b55fa915023a02ab6967765a665493b0b13fc33209a60312500d019a
        );
        (bytes32[] memory txMerkleProof, ) = BTCStyleMerkle.generateMerkleProof(
            txHashes,
            0
        );

        // Complete the bridge out by proposer
        IDogechain.SPVProof[] memory proofs = new IDogechain.SPVProof[](1);
        proofs[0] = IDogechain.SPVProof({
            // txHash: BTCStyleMerkle.reverseBytes32(0x6f35b9e9cff6e788b6fb9e4a707a972081fe3a28369bca9e4319b10a4751e68f),
            txMerkleProof: txMerkleProof,
            txIndex: 0,
            blockHeader: IDogechain.BlockHeader({
                version: 6422788,
                prevBlock: BTCStyleMerkle.reverseBytes32(
                    0x0bbfc4b2d3b8e4e3e66d3a4dae6338c0d7a9ae26040575be1f15254ad602d40c
                ),
                merkleRoot: BTCStyleMerkle.reverseBytes32(
                    0xa2f10e9e2dc6dede16d9775395dc015572c4e3a128e6aebe7bc9780f754d296a
                ),
                timestamp: 1737618144,
                bits: 0x197c63d0,
                nonce: 0x0000000000000000000000000000000000000000000000000000000000000000
            }),
            blockMerkleProof: blockMerkleProof,
            blockIndex: 1,
            destEvmAddress: address(proposer),
            amount: 100,
            txBytes: hex"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3503eec9540fe4b883e5bda9e7a59ee4bb99e9b1bc205b323032352d30312d32335430373a34323a32342e3534373132313330355a5dffffffff01a01305efe80000001976a91447b6ccaa4525a3e9a2806d7aeadc978b4933553788ac00000000"
        });

        uint256[] memory taskIds = new uint256[](1);
        taskIds[0] = 0;

        // bridge.bridgeOutFinish(0, proofs[0], taskIds);
        (
            address from,
            uint256 destAmount,
            bytes20 destDogecoinAddress,
            uint8 status
        ) = bridge.bridgeOutTasks(0);
        assertEq(status, 5);
        assertEq(from, user);
        assertEq(destAmount, 500);
        assertEq(destDogecoinAddress, bytes20("destination-address"));
        assertEq(dogeToken.balanceOf(address(bridge)), 0); // Tokens burned
        vm.stopPrank();
    }

    function test_Stake() public {
        // TODO: ...
    }
}
