// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

interface IDogeToken {
    function mint(address to, uint256 amount) external;
    function burn(uint256 amount) external;
    function setBridge(address _bridge) external;
    function balanceOf(address account) external view returns (uint256);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
}
