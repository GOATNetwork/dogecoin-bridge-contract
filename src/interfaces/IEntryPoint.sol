// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

contract IEntryPoint {
    event SetSigner(address indexed newSigner);
    event SetParticipant(address[] participants);
    event SubmitterChosen(address indexed newSubmitter);
    event SubmitterRotationRequested(address indexed requester, address indexed currentSubmitter);

    error EmptyOperationsArray();
    error InvalidSigner(address sender);
    error IncorrectSubmitter(address sender, address submitter);
    error RotationWindowNotPassed(uint256 current, uint256 window);
    error InvalidAddress();
    error ExceedMaxOptCount();
    error NotEligibleForPending(uint64 taskId);
}
