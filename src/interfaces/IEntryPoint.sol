// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

contract IEntryPoint {
    event Stake(address indexed staker, uint256 amount);
    event Unstake(address indexed staker, uint256 amount);
    event SetSigner(address indexed newSigner);
    event StakeThresholdUpdated(uint256 newThreshold);
    event SetProposer(address[] participants);
    event SubmitterChosen(address indexed newSubmitter);
    event SubmitterRotationRequested(
        address indexed requester,
        address indexed currentSubmitter
    );

    error IncorrectSubmitter(address sender, address submitter);
    error RotationWindowNotPassed(uint256 current, uint256 window);
}
