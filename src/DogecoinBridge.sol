// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "./interfaces/IDogechain.sol";
import "./interfaces/IDogeToken.sol";
import "./libraries/DogeTransactionParser.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";

contract DogecoinBridge is UUPSUpgradeable, AccessControlUpgradeable {
    struct BridgeOutTask {
        address from;
        uint256 destAmount;
        bytes20 destDogecoinAddress;
        uint8 status; // 1: create, 2: prepare, 3: rbf, 4: cancel, 5: finish
    }

    bytes32 public constant OWNER_ROLE = keccak256("OWNER_ROLE");
    bytes32 public constant ENTRYPOINT_ROLE = keccak256("ENTRYPOINT_ROLE");

    mapping(bytes32 => bool) public bridgeInTxids;
    mapping(uint256 => BridgeOutTask) public bridgeOutTasks;
    uint256 public latestTaskId;
    uint256 public feeRate; // Basis points (1% = 100)
    uint256 public feeBalance;
    uint256 public bridgedInAmount; // log the amount of bridged in
    uint256 public bridgedOutAmount; // log the amount of bridged out
    IDogeToken public dogeToken;
    IDogechain public dogechain;
    bytes20 public dogecoinBridgePK; // dogecoin bridge-in public key hash
    bytes4 public opReturnMagicPrefix; // GTV1
    DogeTransactionParser.Network public dogecoinNetwork; // dogecoin network, 0: mainnet, 1: testnet, 2: regtest

    event BridgeIn(
        address indexed destEvmAddress,
        uint256 amount,
        bytes32 txHash
    );
    /**
     * @dev Bridge out event
     * @param taskId The task ID
     * @param from The address of the user
     * @param destAmount The amount of the destination currency (18 decimals, bridge should convert to 8 decimals on Dogechain)
     * @param fee The fee for the bridge out
     * @param destDogecoinAddress The destination address (Dogechain address)
     */
    event BridgeOutProposed(
        uint256 taskId,
        address indexed from,
        uint256 destAmount,
        uint256 fee,
        bytes20 destDogecoinAddress
    );
    event BridgeOutFinished(uint256[] taskIds);
    event FeesWithdrawn(address indexed owner, uint256 amount);
    event FeeRateUpdated(address indexed owner, uint256 feeRate);
    event DogecoinBridgePKUpdated(
        address indexed owner,
        bytes20 dogecoinBridgePK
    );

    function initialize(
        address _entryPoint,
        address _dogeToken,
        address _dogechain,
        uint256 _feeRate,
        bytes20 _dogecoinBridgePK,
        bytes4 _opReturnMagicPrefix,
        DogeTransactionParser.Network _dogecoinNetwork
    ) external initializer {
        __AccessControl_init();
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OWNER_ROLE, msg.sender);
        _grantRole(ENTRYPOINT_ROLE, _entryPoint);

        __UUPSUpgradeable_init();
        dogeToken = IDogeToken(_dogeToken);
        dogechain = IDogechain(_dogechain);
        feeRate = _feeRate;
        dogecoinBridgePK = _dogecoinBridgePK;
        opReturnMagicPrefix = _opReturnMagicPrefix;
        dogecoinNetwork = _dogecoinNetwork;
        emit FeeRateUpdated(msg.sender, _feeRate);
        emit DogecoinBridgePKUpdated(msg.sender, _dogecoinBridgePK);
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(OWNER_ROLE) {}

    function bridgeIn(
        IDogechain.BridgeTransaction[] memory bridgeTxs,
        uint256 batchId
    ) external onlyRole(ENTRYPOINT_ROLE) {
        IDogechain.Batch memory batch = dogechain.getBatch(batchId);
        require(batch.rootHash != bytes32(0), "Invalid batch");

        uint256 totalAmount = 0;
        for (uint256 i = 0; i < bridgeTxs.length; i++) {
            bytes32 txid = DogeTransactionParser.getTxid(bridgeTxs[i].txBytes);
            require(txid != bytes32(0), "Invalid txid");
            require(
                bridgeTxs[i].destEvmAddress != address(0),
                "Invalid destEvmAddress"
            );
            require(bridgeInTxids[txid] == false, "Txid already processed");

            // check opReturnMagicPrefix, p2pkhOutput, amount, destEvmAddress from bridgeTxs[i].txBytes
            DogeTransactionParser.P2PKHOutput memory p2pkhOutput;
            bytes memory opReturnData;
            bool isP2PKHWithOpReturn;
            (p2pkhOutput, opReturnData, isP2PKHWithOpReturn) = DogeTransactionParser.parseBridgeInP2PKHTransaction(bridgeTxs[i].txBytes);
            require(isP2PKHWithOpReturn, "Invalid transaction");
            require(p2pkhOutput.publicKeyHash == dogecoinBridgePK, "Invalid dogecoin bridge address");
            require(p2pkhOutput.value == bridgeTxs[i].amount, "Invalid amount");
            require(opReturnData.length == 24 && bytes4(opReturnData) == opReturnMagicPrefix, "Invalid OP_RETURN data");

            bytes memory slicedData = new bytes(20);
            for (uint256 j = 4; j < 24; j++) {
                slicedData[j - 4] = opReturnData[j];
            }
            address destAddress = address(uint160(bytes20(slicedData)));
            require(destAddress == bridgeTxs[i].destEvmAddress, "Invalid destination address");

            dogeToken.mint(destAddress, bridgeTxs[i].amount);
            totalAmount += bridgeTxs[i].amount;
            bridgeInTxids[txid] = true;
            emit BridgeIn(destAddress, bridgeTxs[i].amount, txid);
        }

        bridgedInAmount += totalAmount;
    }

    function bridgeOut(
        uint256 amount,
        bytes20 destDogecoinAddress
    ) external payable {
        require(amount > 0, "Amount must be greater than 0");
        require(
            destDogecoinAddress != bytes20(0),
            "Invalid destination address"
        );

        uint256 fee = (amount * feeRate) / 10000;
        require(amount > fee, "Amount must be greater than fee");
        // TODO: convert destAmount to 8 decimals
        uint256 destAmount = amount - fee;

        require(
            dogeToken.balanceOf(msg.sender) >= amount,
            "Insufficient balance"
        );
        dogeToken.transferFrom(msg.sender, address(this), amount);

        uint256 taskId = latestTaskId++;
        bridgeOutTasks[taskId] = BridgeOutTask({
            from: msg.sender,
            destAmount: destAmount,
            destDogecoinAddress: destDogecoinAddress,
            status: 1
        });

        // add fee to balance
        feeBalance += fee;

        emit BridgeOutProposed(
            taskId,
            msg.sender,
            destAmount,
            fee,
            destDogecoinAddress
        );
    }

    // function bridgeOutPrepare(bytes memory txBytes, uint256[] memory taskIds) external {
    //     require(txBytes.length > 0, "Invalid txBytes");
    //     require(taskIds.length > 0, "Invalid taskIds");

    //     for (uint256 i = 0; i < taskIds.length; i++) {
    //         BridgeOutTask storage task = bridgeOutTasks[taskIds[i]];
    //         require(task.status == 1, "Task is not in create status");
    //         task.status = 2;
    //     }
    // }

    // function bridgeOutRBF(bytes memory txBytes, uint256[] memory taskIds) external {
    //     require(txBytes.length > 0, "Invalid txBytes");
    //     require(taskIds.length > 0, "Invalid taskIds");

    //     for (uint256 i = 0; i < taskIds.length; i++) {
    //         BridgeOutTask storage task = bridgeOutTasks[taskIds[i]];
    //         require(task.status == 2, "Task is not in prepare status");
    //         task.status = 3;
    //     }
    // }

    /**
     * @dev Bridge out finish
     * @param batchId The batch ID
     * @param bridgeTx The bridge transaction, one txid deals many bridge out tasks
     * @param taskIds The task IDs
     */
    function bridgeOutFinish(
        uint256 batchId,
        IDogechain.BridgeTransaction memory bridgeTx,
        uint256[] memory taskIds
    ) external onlyRole(ENTRYPOINT_ROLE) {
        bytes32 txid = DogeTransactionParser.getTxid(bridgeTx.txBytes);
        require(txid != bytes32(0), "Invalid txid");
        require(taskIds.length > 0, "Invalid taskIds");

        // TODO: check doublehash(bridgeTx.txBytes) with bridgeTx.txHash

        // TODO: extract p2pkhOutputs from bridgeTx.txBytes
        // p2pkhOutputs = dogechain.extractBridgeOutTransaction(bridgeTx.txBytes);

        for (uint256 i = 0; i < taskIds.length; i++) {
            uint256 taskId = taskIds[i];
            BridgeOutTask storage task = bridgeOutTasks[taskId];
            require(task.from != address(0), "Task does not exist");
            require(task.status == 1, "Task is not in create status");

            // TODO enable this after real dogecoin bridge-in transaction is implemented
            // require(task.destAmount == p2pkhOutputs[i].amount, "Invalid amount");
            // require(task.destDogecoinAddress == p2pkhOutputs[i].dogecoinAddress, "Invalid destination address");

            task.status = 5;
            dogeToken.burn(task.destAmount);
            // TODO: convert destAmount to 18 decimals
            bridgedOutAmount += task.destAmount;
        }

        emit BridgeOutFinished(taskIds);
    }

    function setFeeRate(uint256 _feeRate) external onlyRole(OWNER_ROLE) {
        feeRate = _feeRate;
        emit FeeRateUpdated(msg.sender, _feeRate);
    }

    function setDogecoinBridgePK(
        bytes20 _dogecoinBridgePK
    ) external onlyRole(OWNER_ROLE) {
        dogecoinBridgePK = _dogecoinBridgePK;
        emit DogecoinBridgePKUpdated(msg.sender, _dogecoinBridgePK);
    }

    function withdrawFees() external onlyRole(OWNER_ROLE) {
        require(feeBalance > 0, "No fees available");
        feeBalance = 0;

        payable(msg.sender).transfer(feeBalance);
        emit FeesWithdrawn(msg.sender, feeBalance);
    }
}
