// SPDX-License-Identifier: MIT
// Chainlink Price Feed Consumer - Simplified for analysis (2024)
pragma solidity ^0.8.0;

/**
 * @title ChainlinkPriceFeed
 * @notice Simplified Chainlink price feed aggregator for security analysis
 * @dev Based on Chainlink AggregatorV3Interface pattern
 */
interface AggregatorV3Interface {
    function decimals() external view returns (uint8);
    function description() external view returns (string memory);
    function version() external view returns (uint256);
    function getRoundData(uint80 _roundId) external view returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    );
    function latestRoundData() external view returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    );
}

contract ChainlinkPriceFeed {
    AggregatorV3Interface internal priceFeed;
    address public owner;

    mapping(address => bool) public authorizedUpdaters;
    uint256 public lastUpdateTime;
    int256 public lastPrice;
    uint256 public heartbeatInterval = 3600; // 1 hour

    event PriceUpdated(int256 price, uint256 timestamp);
    event HeartbeatIntervalUpdated(uint256 newInterval);

    modifier onlyOwner() {
        require(msg.sender == owner, "NOT_OWNER");
        _;
    }

    constructor(address _priceFeed) {
        priceFeed = AggregatorV3Interface(_priceFeed);
        owner = msg.sender;
    }

    /**
     * @notice Returns the latest price
     * @dev Vulnerability: No staleness check
     */
    function getLatestPrice() public view returns (int256) {
        (, int256 price, , , ) = priceFeed.latestRoundData();
        return price;
    }

    /**
     * @notice Returns price with staleness check
     * @dev Vulnerability: Incomplete validation - missing roundId check
     */
    function getLatestPriceWithCheck() public view returns (int256) {
        (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = priceFeed.latestRoundData();

        // Vulnerability: Price can be negative, no check
        require(updatedAt != 0, "ROUND_NOT_COMPLETE");
        require(block.timestamp - updatedAt < heartbeatInterval, "STALE_PRICE");

        // Missing: require(answeredInRound >= roundId, "STALE_ROUND");
        // Missing: require(answer > 0, "NEGATIVE_PRICE");

        return answer;
    }

    /**
     * @notice Get price for a specific round
     * @dev Vulnerability: No access control on historical data
     */
    function getHistoricalPrice(uint80 roundId) public view returns (int256) {
        (, int256 price, , uint256 updatedAt, ) = priceFeed.getRoundData(roundId);
        require(updatedAt > 0, "ROUND_NOT_COMPLETE");
        return price;
    }

    /**
     * @notice Derive price from two feeds
     * @dev Vulnerability: Integer overflow possible in multiplication
     */
    function getDerivedPrice(
        address _base,
        address _quote,
        uint8 _decimals
    ) public view returns (int256) {
        (, int256 basePrice, , , ) = AggregatorV3Interface(_base).latestRoundData();
        (, int256 quotePrice, , , ) = AggregatorV3Interface(_quote).latestRoundData();

        uint8 baseDecimals = AggregatorV3Interface(_base).decimals();
        uint8 quoteDecimals = AggregatorV3Interface(_quote).decimals();

        // Vulnerability: No overflow check, price manipulation possible
        int256 derivedPrice = (basePrice * int256(10 ** uint256(_decimals))) / quotePrice;

        return derivedPrice;
    }

    /**
     * @notice Set new heartbeat interval
     * @dev Vulnerability: No bounds check, can be set to 0 or very large value
     */
    function setHeartbeatInterval(uint256 _interval) external onlyOwner {
        heartbeatInterval = _interval;
        emit HeartbeatIntervalUpdated(_interval);
    }

    /**
     * @notice Emergency price override
     * @dev Vulnerability: Centralization risk, no timelock
     */
    function emergencySetPrice(int256 _price) external onlyOwner {
        lastPrice = _price;
        lastUpdateTime = block.timestamp;
        emit PriceUpdated(_price, block.timestamp);
    }

    /**
     * @notice Add authorized updater
     * @dev Vulnerability: No multi-sig requirement for critical operation
     */
    function addAuthorizedUpdater(address _updater) external onlyOwner {
        authorizedUpdaters[_updater] = true;
    }

    /**
     * @notice Remove authorized updater
     */
    function removeAuthorizedUpdater(address _updater) external onlyOwner {
        authorizedUpdaters[_updater] = false;
    }

    /**
     * @notice Transfer ownership
     * @dev Vulnerability: No two-step ownership transfer
     */
    function transferOwnership(address _newOwner) external onlyOwner {
        require(_newOwner != address(0), "ZERO_ADDRESS");
        owner = _newOwner;
    }
}
