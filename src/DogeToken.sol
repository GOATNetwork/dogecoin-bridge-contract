// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "./interfaces/IDogeToken.sol";

contract DogeToken is IDogeToken, ERC20, Ownable {
    address public bridge;

    constructor() Ownable(msg.sender) ERC20("Dogecoin", "DOGE") {}

    function setBridge(address _bridge) external override onlyOwner {
        require(_bridge != address(0), "Invalid bridge address");
        bridge = _bridge;
    }

    function mint(address to, uint256 amount) external override {
        require(msg.sender == bridge, "Only bridge can mint");
        _mint(to, amount);
    }

    function burn(uint256 amount) external override {
        _burn(msg.sender, amount);
    }

    function balanceOf(
        address account
    ) public view override(ERC20, IDogeToken) returns (uint256) {
        return super.balanceOf(account);
    }

    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) public override(ERC20, IDogeToken) returns (bool) {
        return super.transferFrom(sender, recipient, amount);
    }
}
