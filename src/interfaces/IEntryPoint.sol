// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

contract IEntryPoint {
    event Stake(address indexed staker, uint256 amount);
    event Unstake(address indexed staker, uint256 amount);
    event SetSigner(address indexed newSigner);
    event StakeThresholdUpdated(uint256 newThreshold);
    event AddProposerRequested(address proposer, uint256 timestamp);
    event RemoveProposerRequested(address proposer, uint256 timestamp);
    event ProposerConfirmed(address proposer, uint256 timestamp);
    event ProposerSelected(address indexed newProposer);

    error IncorrectProposer(address sender, address proposer);
    error RotationWindowNotPassed(uint256 current, uint256 window);
}
