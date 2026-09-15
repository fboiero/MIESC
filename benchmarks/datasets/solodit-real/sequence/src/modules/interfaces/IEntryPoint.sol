// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IEntryPoint {

  function depositTo(
    address account
  ) external payable;

}
