// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "./interfaces/IDogechain.sol";
import "./interfaces/IDogeToken.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract DogecoinBridge is UUPSUpgradeable, OwnableUpgradeable {
    struct BridgeOutTask {
        address from;
        uint256 destAmount;
        bytes20 destDogecoinAddress;
        bool completed;
    }

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

    event BridgeIn(address indexed destEvmAddress, uint256 amount, bytes32 txHash);
    /**
     * @dev Bridge out event
     * @param taskId The task ID
     * @param from The address of the user
     * @param destAmount The amount of the destination currency (18 decimals, bridge should convert to 8 decimals on Dogechain)
     * @param fee The fee for the bridge out
     * @param destDogecoinAddress The destination address (Dogechain address)
     */
    event BridgeOutProposed(
        uint256 taskId, address indexed from, uint256 destAmount, uint256 fee, bytes20 destDogecoinAddress
    );
    event BridgeOutFinished(uint256[] taskIds);
    event FeesWithdrawn(address indexed owner, uint256 amount);
    event FeeRateUpdated(address indexed owner, uint256 feeRate);
    event DogecoinBridgePKUpdated(address indexed owner, bytes20 dogecoinBridgePK);

    function initialize(address _dogeToken, address _dogechain, uint256 _feeRate, bytes20 _dogecoinBridgePK)
        external
        initializer
    {
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
        dogeToken = IDogeToken(_dogeToken);
        dogechain = IDogechain(_dogechain);
        feeRate = _feeRate;
        dogecoinBridgePK = _dogecoinBridgePK;
        emit FeeRateUpdated(msg.sender, _feeRate);
        emit DogecoinBridgePKUpdated(msg.sender, _dogecoinBridgePK);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    modifier onlyAdmin() {
        require(dogechain.admins(msg.sender), "Caller is not an admin");
        _;
    }

    function bridgeIn(IDogechain.SPVProof[] memory proofs, uint256 batchId) external onlyAdmin {
        IDogechain.Batch memory batch = dogechain.getBatch(batchId);
        require(batch.rootHash != bytes32(0), "Invalid batch");

        uint256 totalAmount = 0;
        for (uint256 i = 0; i < proofs.length; i++) {
            require(dogechain.validateTransaction(batchId, proofs[i]), "Invalid SPV proof");

            // TODO: check doublehash(proofs[i].txBytes) with proofs[i].txHash

            // TODO: extract amount, destEvmAddress from proofs[i].txBytes
            // (uint256 amount, address destEvmAddress, bytes20 dogecoinAddress) = dogechain.extractBridgeInTransaction(proofs[i].txBytes);

            // TODO enable this after real dogecoin bridge-in transaction is implemented
            // require(amount == proofs[i].amount, "Invalid amount");
            // require(destEvmAddress == proofs[i].destEvmAddress, "Invalid destination address");
            // require(dogecoinAddress == dogecoinBridgeAddress, "Invalid dogecoin bridge address");
            dogeToken.mint(proofs[i].destEvmAddress, proofs[i].amount);
            totalAmount += proofs[i].amount;
            bridgeInTxids[proofs[i].txHash] = true;
            emit BridgeIn(proofs[i].destEvmAddress, proofs[i].amount, proofs[i].txHash);
        }

        // TODO: recheck the unit test
        bridgedInAmount += totalAmount;
    }

    function bridgeOut(uint256 amount, bytes20 destDogecoinAddress) external payable {
        require(amount > 0, "Amount must be greater than 0");
        require(destDogecoinAddress != bytes20(0), "Invalid destination address");

        uint256 fee = (amount * feeRate) / 10000;
        require(amount > fee, "Amount must be greater than fee");
        // TODO: convert destAmount to 8 decimals
        uint256 destAmount = amount - fee;

        require(dogeToken.balanceOf(msg.sender) >= amount, "Insufficient balance");
        dogeToken.transferFrom(msg.sender, address(this), amount);

        uint256 taskId = latestTaskId++;
        bridgeOutTasks[taskId] = BridgeOutTask({
            from: msg.sender,
            destAmount: destAmount,
            destDogecoinAddress: destDogecoinAddress,
            completed: false
        });

        // add fee to balance
        feeBalance += fee;

        emit BridgeOutProposed(taskId, msg.sender, destAmount, fee, destDogecoinAddress);
    }

    /**
     * @dev Bridge out finish
     * @param batchId The batch ID
     * @param proof The SPV proof, one txid deals many bridge out tasks
     * @param taskIds The task IDs
     */
    function bridgeOutFinish(uint256 batchId, IDogechain.SPVProof memory proof, uint256[] memory taskIds)
        external
        onlyAdmin
    {
        require(proof.txHash != bytes32(0), "Invalid txHash");
        require(taskIds.length > 0, "Invalid taskIds");
        require(dogechain.validateTransaction(batchId, proof), "Invalid SPV proof");

        // TODO: check doublehash(proof.txBytes) with proof.txHash

        // TODO: extract p2pkhOutputs from proof.txBytes
        // p2pkhOutputs = dogechain.extractBridgeOutTransaction(proof.txBytes);

        for (uint256 i = 0; i < taskIds.length; i++) {
            uint256 taskId = taskIds[i];
            BridgeOutTask storage task = bridgeOutTasks[taskId];
            require(task.from != address(0), "Task does not exist");
            require(!task.completed, "Task already completed");

            // TODO enable this after real dogecoin bridge-in transaction is implemented
            // require(task.destAmount == p2pkhOutputs[i].amount, "Invalid amount");
            // require(task.destDogecoinAddress == p2pkhOutputs[i].dogecoinAddress, "Invalid destination address");

            task.completed = true;
            dogeToken.burn(task.destAmount);
            // TODO: convert destAmount to 18 decimals
            bridgedOutAmount += task.destAmount;
        }

        emit BridgeOutFinished(taskIds);
    }

    function setFeeRate(uint256 _feeRate) external onlyOwner {
        feeRate = _feeRate;
        emit FeeRateUpdated(msg.sender, _feeRate);
    }

    function setDogecoinBridgePK(bytes20 _dogecoinBridgePK) external onlyOwner {
        dogecoinBridgePK = _dogecoinBridgePK;
        emit DogecoinBridgePKUpdated(msg.sender, _dogecoinBridgePK);
    }

    function withdrawFees() external onlyOwner {
        require(feeBalance > 0, "No fees available");
        feeBalance = 0;

        payable(msg.sender).transfer(feeBalance);
        emit FeesWithdrawn(msg.sender, feeBalance);
    }
}
