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
        bool completed;
    }

    mapping(uint256 => BridgeOutTask) public bridgeOutTasks;
    uint256 public latestTaskId;
    uint256 public feeRate; // Basis points (1% = 100)
    uint256 public feeBalance;
    IDogeToken public dogeToken;
    IDogechain public dogechain;

    event BridgeIn(address indexed from, uint256 batchId, uint256 totalAmount, uint256 proofCount);
    /**
     * @dev Bridge out event
     * @param taskId The task ID
     * @param from The address of the user
     * @param destAmount The amount of the destination currency (18 decimals, bridge should convert to 8 decimals on Dogechain)
     * @param fee The fee for the bridge out
     * @param destAddress The destination address (Dogechain address)
     */
    event BridgeOutProposed(uint256 taskId, address indexed from, uint256 destAmount, uint256 fee, string destAddress);
    event BridgeOutFinished(uint256[] taskIds);
    event FeesWithdrawn(address indexed owner, uint256 amount);
    event FeeRateUpdated(address indexed owner, uint256 feeRate);

    function initialize(address _dogeToken, address _dogechain, uint256 _feeRate) external initializer {
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
        dogeToken = IDogeToken(_dogeToken);
        dogechain = IDogechain(_dogechain);
        feeRate = _feeRate;
        emit FeeRateUpdated(msg.sender, _feeRate);
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

            totalAmount += proofs[i].amount;
        }

        dogeToken.mint(msg.sender, totalAmount);
        emit BridgeIn(msg.sender, batchId, totalAmount, proofs.length);
    }

    function bridgeOut(uint256 amount, string memory destAddress) external payable {
        require(amount > 0, "Amount must be greater than 0");
        require(bytes(destAddress).length > 0, "Invalid destination address");

        uint256 fee = (amount * feeRate) / 10000;
        require(amount > fee, "Amount must be greater than fee");
        uint256 destAmount = amount - fee;

        require(dogeToken.balanceOf(msg.sender) >= amount, "Insufficient balance");
        dogeToken.transferFrom(msg.sender, address(this), amount);

        uint256 taskId = latestTaskId++;
        bridgeOutTasks[taskId] = BridgeOutTask({from: msg.sender, destAmount: destAmount, completed: false});

        // add fee to balance
        feeBalance += fee;

        emit BridgeOutProposed(taskId, msg.sender, destAmount, fee, destAddress);
    }

    function bridgeOutFinish(uint256 batchId, IDogechain.SPVProof[] memory proofs, uint256[] memory taskIds)
        external
        onlyAdmin
    {
        require(proofs.length == taskIds.length, "Mismatched inputs");

        for (uint256 i = 0; i < taskIds.length; i++) {
            uint256 taskId = taskIds[i];
            BridgeOutTask storage task = bridgeOutTasks[taskId];
            require(task.from != address(0), "Task does not exist");
            require(!task.completed, "Task already completed");

            require(dogechain.validateTransaction(batchId, proofs[i]), "Invalid SPV proof");

            task.completed = true;
            dogeToken.burn(task.destAmount);
        }

        emit BridgeOutFinished(taskIds);
    }

    function setFeeRate(uint256 _feeRate) external onlyOwner {
        feeRate = _feeRate;
        emit FeeRateUpdated(msg.sender, _feeRate);
    }

    function withdrawFees() external onlyOwner {
        require(feeBalance > 0, "No fees available");
        feeBalance = 0;

        payable(msg.sender).transfer(feeBalance);
        emit FeesWithdrawn(msg.sender, feeBalance);
    }
}
