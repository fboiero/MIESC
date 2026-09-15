pragma solidity ^0.8.0;
import "./Derived.sol";
interface IDerived { function withdraw() external; }
contract Router {
    function callWithdraw(address x) external { IDerived(x).withdraw(); }
}
