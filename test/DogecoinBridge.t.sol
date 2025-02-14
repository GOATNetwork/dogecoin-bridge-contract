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
        vm.startPrank(owner);
        (tssSigner, tssKey) = makeAddrAndKey("tss");

        // Deploy and initialize contracts
        entryPoint = new EntryPointUpgradeable();
        address[] memory proposers = new address[](1);
        proposers[0] = proposer;
        entryPoint.initialize(tssSigner, proposers);

        dogeToken = new DogeToken();
        dogeToken.initialize();

        dogechain = new Dogechain();
        dogechain.initialize(address(entryPoint));

        bridge = new DogecoinBridge();
        bridge.initialize(
            address(entryPoint),
            address(dogeToken),
            address(dogechain),
            10,
            bytes20(0)
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

    function testBridgeIn() public {
        vm.startPrank(address(entryPoint));

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

        IDogechain.SPVProof[] memory proofs = new IDogechain.SPVProof[](1);
        proofs[0] = IDogechain.SPVProof({
            txHash: BTCStyleMerkle.reverseBytes32(
                0x6f35b9e9cff6e788b6fb9e4a707a972081fe3a28369bca9e4319b10a4751e68f
            ),
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
            txBytes: new bytes(0)
        });

        bool blockProofValidation = BTCStyleMerkle.verifyMerkleProof(
            blockHashMerkleRoot,
            blockMerkleProof,
            BTCStyleMerkle.reverseBytes32(
                0xfb4cc1df87acfe4bd5998d885c664edcd949ac8d2f24affa9a2bfe9f7d3945a5
            ),
            1
        );
        assertTrue(blockProofValidation);

        // Bridge in tokens
        bridge.bridgeIn(proofs, 0);

        assertEq(dogeToken.balanceOf(proposer), 100);
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
            txHash: BTCStyleMerkle.reverseBytes32(
                0x6f35b9e9cff6e788b6fb9e4a707a972081fe3a28369bca9e4319b10a4751e68f
            ),
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
            txBytes: new bytes(0)
        });

        uint256[] memory taskIds = new uint256[](1);
        taskIds[0] = 0;

        bridge.bridgeOutFinish(0, proofs[0], taskIds);
        (
            address from,
            uint256 destAmount,
            bytes20 destDogecoinAddress,
            bool completed
        ) = bridge.bridgeOutTasks(0);
        assertTrue(completed);
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

        bytes memory callData = abi.encodeWithSelector(
            dogechain.submitBatch.selector,
            5556717,
            3,
            blockHashMerkleRoot
        );
        bytes memory encodedData = abi.encodePacked(
            callData,
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
        entryPoint.verifyAndCall(address(dogechain), callData, signature);

        // Fail: incorrect signature
        vm.startPrank(proposer);
        vm.expectRevert("Invalid Signer");
        entryPoint.verifyAndCall(address(dogechain), callData, signature);

        // Success
        (v, r, s) = vm.sign(tssKey, digest);
        signature = abi.encodePacked(r, s, v);
        entryPoint.verifyAndCall(address(dogechain), callData, signature);
    }
}
