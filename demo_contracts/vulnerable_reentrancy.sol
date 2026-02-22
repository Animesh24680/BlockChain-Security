// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance");

        // BUG: External call BEFORE state update
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");

        // State update happens AFTER external call — reentrancy window
        balances[msg.sender] = 0;
    }
}
