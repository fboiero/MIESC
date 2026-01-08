// SPDX-License-Identifier: MIT
// Lido stETH Token - Simplified for analysis (2024)
pragma solidity ^0.8.0;

/**
 * @title stETH - Liquid Staking Token
 * @notice Simplified version of Lido's stETH for security analysis
 * @dev Based on Lido stETH mainnet contract
 */
contract stETH {
    string public name = "Liquid staked Ether 2.0";
    string public symbol = "stETH";
    uint8 public decimals = 18;

    mapping(address => uint256) private _shares;
    mapping(address => mapping(address => uint256)) private _allowances;

    uint256 private _totalShares;
    uint256 private _totalPooledEther;

    address public lido;
    bool private _stopped;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event TransferShares(address indexed from, address indexed to, uint256 sharesValue);

    modifier whenNotStopped() {
        require(!_stopped, "CONTRACT_IS_STOPPED");
        _;
    }

    constructor() {
        lido = msg.sender;
    }

    function totalSupply() public view returns (uint256) {
        return _totalPooledEther;
    }

    function getTotalShares() public view returns (uint256) {
        return _totalShares;
    }

    function balanceOf(address _account) public view returns (uint256) {
        return getPooledEthByShares(_shares[_account]);
    }

    function sharesOf(address _account) public view returns (uint256) {
        return _shares[_account];
    }

    function getSharesByPooledEth(uint256 _ethAmount) public view returns (uint256) {
        if (_totalPooledEther == 0) {
            return 0;
        }
        return _ethAmount * _totalShares / _totalPooledEther;
    }

    function getPooledEthByShares(uint256 _sharesAmount) public view returns (uint256) {
        if (_totalShares == 0) {
            return 0;
        }
        return _sharesAmount * _totalPooledEther / _totalShares;
    }

    function transfer(address _recipient, uint256 _amount) external returns (bool) {
        _transfer(msg.sender, _recipient, _amount);
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256) {
        return _allowances[_owner][_spender];
    }

    function approve(address _spender, uint256 _amount) external returns (bool) {
        _approve(msg.sender, _spender, _amount);
        return true;
    }

    function transferFrom(address _sender, address _recipient, uint256 _amount) external returns (bool) {
        uint256 currentAllowance = _allowances[_sender][msg.sender];
        require(currentAllowance >= _amount, "ALLOWANCE_EXCEEDED");
        _transfer(_sender, _recipient, _amount);
        _approve(_sender, msg.sender, currentAllowance - _amount);
        return true;
    }

    // Vulnerability: Potential front-running in share transfers
    function transferShares(address _recipient, uint256 _sharesAmount) external returns (uint256) {
        _transferShares(msg.sender, _recipient, _sharesAmount);
        uint256 tokensAmount = getPooledEthByShares(_sharesAmount);
        emit Transfer(msg.sender, _recipient, tokensAmount);
        return tokensAmount;
    }

    // Vulnerability: No slippage protection
    function transferSharesFrom(address _sender, address _recipient, uint256 _sharesAmount) external returns (uint256) {
        uint256 tokensAmount = getPooledEthByShares(_sharesAmount);
        uint256 currentAllowance = _allowances[_sender][msg.sender];
        require(currentAllowance >= tokensAmount, "ALLOWANCE_EXCEEDED");
        _transferShares(_sender, _recipient, _sharesAmount);
        _approve(_sender, msg.sender, currentAllowance - tokensAmount);
        emit Transfer(_sender, _recipient, tokensAmount);
        return tokensAmount;
    }

    function _transfer(address _sender, address _recipient, uint256 _amount) internal whenNotStopped {
        uint256 sharesToTransfer = getSharesByPooledEth(_amount);
        _transferShares(_sender, _recipient, sharesToTransfer);
        emit Transfer(_sender, _recipient, _amount);
    }

    function _transferShares(address _sender, address _recipient, uint256 _sharesAmount) internal {
        require(_sender != address(0), "TRANSFER_FROM_ZERO");
        require(_recipient != address(0), "TRANSFER_TO_ZERO");
        require(_recipient != address(this), "TRANSFER_TO_STETH");

        uint256 currentSenderShares = _shares[_sender];
        require(_sharesAmount <= currentSenderShares, "BALANCE_EXCEEDED");

        _shares[_sender] = currentSenderShares - _sharesAmount;
        _shares[_recipient] = _shares[_recipient] + _sharesAmount;

        emit TransferShares(_sender, _recipient, _sharesAmount);
    }

    function _approve(address _owner, address _spender, uint256 _amount) internal {
        require(_owner != address(0), "APPROVE_FROM_ZERO");
        require(_spender != address(0), "APPROVE_TO_ZERO");
        _allowances[_owner][_spender] = _amount;
        emit Approval(_owner, _spender, _amount);
    }

    // Vulnerability: Centralization risk - single point of failure
    function mintShares(address _recipient, uint256 _sharesAmount) external {
        require(msg.sender == lido, "ONLY_LIDO");
        require(_recipient != address(0), "MINT_TO_ZERO");

        _totalShares = _totalShares + _sharesAmount;
        _shares[_recipient] = _shares[_recipient] + _sharesAmount;
    }

    // Vulnerability: No timelock on critical operations
    function burnShares(address _account, uint256 _sharesAmount) external {
        require(msg.sender == lido, "ONLY_LIDO");
        require(_account != address(0), "BURN_FROM_ZERO");
        require(_sharesAmount <= _shares[_account], "BALANCE_EXCEEDED");

        _totalShares = _totalShares - _sharesAmount;
        _shares[_account] = _shares[_account] - _sharesAmount;
    }

    function setTotalPooledEther(uint256 _amount) external {
        require(msg.sender == lido, "ONLY_LIDO");
        _totalPooledEther = _amount;
    }

    function stop() external {
        require(msg.sender == lido, "ONLY_LIDO");
        _stopped = true;
    }

    function resume() external {
        require(msg.sender == lido, "ONLY_LIDO");
        _stopped = false;
    }
}
