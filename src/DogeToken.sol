// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "./interfaces/IDogeToken.sol";

contract DogeToken is IDogeToken, ERC20Upgradeable, OwnableUpgradeable {
    address public bridge;

    function initialize() external initializer {
        __Ownable_init(msg.sender);
        __ERC20_init("Dogecoin", "DOGE");
    }

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

    function balanceOf(address account) public view override(ERC20Upgradeable, IDogeToken) returns (uint256) {
        return super.balanceOf(account);
    }

    function transferFrom(address sender, address recipient, uint256 amount) public override(ERC20Upgradeable, IDogeToken) returns (bool) {
        return super.transferFrom(sender, recipient, amount);
    }
}