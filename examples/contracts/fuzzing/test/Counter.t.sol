// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Counter} from "../src/Counter.sol";

contract CounterTest {
    Counter internal counter;

    function setUp() public {
        counter = new Counter();
        counter.setNumber(0);
    }

    // Passing fuzz test: setNumber round-trips any input.
    function testFuzz_SetNumber(uint256 x) public {
        counter.setNumber(x);
        require(counter.number() == x, "roundtrip");
    }

    // Failing fuzz test: a false invariant for most inputs, so the campaign
    // reports a property violation that becomes a Foundry finding.
    function testFuzz_NeverLarge(uint256 x) public {
        counter.setNumber(x);
        require(counter.number() < 1000, "number too large");
    }
}
