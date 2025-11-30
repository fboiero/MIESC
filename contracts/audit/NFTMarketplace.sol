// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title NFTMarketplace
 * @notice NFT marketplace with multiple security vulnerabilities
 * @dev Contains signature replay, front-running, and business logic flaws
 */

interface IERC721 {
    function ownerOf(uint256 tokenId) external view returns (address);
    function transferFrom(address from, address to, uint256 tokenId) external;
    function approve(address to, uint256 tokenId) external;
    function getApproved(uint256 tokenId) external view returns (address);
    function isApprovedForAll(address owner, address operator) external view returns (bool);
}

contract NFTMarketplace {
    struct Listing {
        address seller;
        address nftContract;
        uint256 tokenId;
        uint256 price;
        uint256 expirationTime;
        bool active;
    }

    struct Offer {
        address buyer;
        uint256 listingId;
        uint256 amount;
        uint256 expirationTime;
        bool active;
    }

    mapping(uint256 => Listing) public listings;
    mapping(uint256 => Offer) public offers;
    mapping(bytes32 => bool) public usedSignatures;

    uint256 public listingCounter;
    uint256 public offerCounter;
    uint256 public platformFee = 250; // 2.5%
    uint256 public constant FEE_DENOMINATOR = 10000;

    address public owner;
    address public feeRecipient;

    event Listed(uint256 indexed listingId, address indexed seller, address nftContract, uint256 tokenId, uint256 price);
    event Sold(uint256 indexed listingId, address indexed buyer, uint256 price);
    event OfferMade(uint256 indexed offerId, address indexed buyer, uint256 listingId, uint256 amount);
    event OfferAccepted(uint256 indexed offerId, address indexed seller);

    constructor() {
        owner = msg.sender;
        feeRecipient = msg.sender;
    }

    // VULNERABILITY 1: No signature replay protection across chains
    function listWithSignature(
        address nftContract,
        uint256 tokenId,
        uint256 price,
        uint256 deadline,
        bytes calldata signature
    ) external {
        require(block.timestamp <= deadline, "Signature expired");

        // VULNERABLE: No chainId in message hash - replay across chains possible
        bytes32 messageHash = keccak256(abi.encodePacked(
            nftContract,
            tokenId,
            price,
            deadline
            // Missing: block.chainid, address(this)
        ));

        // VULNERABILITY 2: Signature malleability not prevented
        address signer = recoverSigner(messageHash, signature);
        require(signer == IERC721(nftContract).ownerOf(tokenId), "Invalid signer");

        // No check if signature was used before on this chain
        _createListing(signer, nftContract, tokenId, price, deadline);
    }

    // VULNERABILITY 3: Front-running vulnerable purchase
    function buy(uint256 listingId) external payable {
        Listing storage listing = listings[listingId];
        require(listing.active, "Listing not active");
        require(block.timestamp <= listing.expirationTime, "Listing expired");
        require(msg.value >= listing.price, "Insufficient payment");

        // VULNERABLE: No slippage protection
        // Price can be changed by seller right before this tx
        listing.active = false;

        uint256 fee = (msg.value * platformFee) / FEE_DENOMINATOR;
        uint256 sellerProceeds = msg.value - fee;

        // Transfer NFT
        IERC721(listing.nftContract).transferFrom(listing.seller, msg.sender, listing.tokenId);

        // Transfer funds
        payable(listing.seller).transfer(sellerProceeds);
        payable(feeRecipient).transfer(fee);

        emit Sold(listingId, msg.sender, msg.value);
    }

    // VULNERABILITY 4: Seller can change price after buyer submits tx
    function updatePrice(uint256 listingId, uint256 newPrice) external {
        Listing storage listing = listings[listingId];
        require(listing.seller == msg.sender, "Not seller");
        require(listing.active, "Listing not active");

        // VULNERABLE: No restrictions on price increase
        // Seller can front-run buy tx and increase price
        listing.price = newPrice;
    }

    // VULNERABILITY 5: Reentrancy in offer acceptance
    function acceptOffer(uint256 offerId) external {
        Offer storage offer = offers[offerId];
        require(offer.active, "Offer not active");
        require(block.timestamp <= offer.expirationTime, "Offer expired");

        Listing storage listing = listings[offer.listingId];
        require(listing.seller == msg.sender, "Not seller");
        require(listing.active, "Listing not active");

        offer.active = false;
        listing.active = false;

        uint256 fee = (offer.amount * platformFee) / FEE_DENOMINATOR;
        uint256 sellerProceeds = offer.amount - fee;

        // VULNERABLE: External calls before all state updates complete
        // Transfer NFT first
        IERC721(listing.nftContract).transferFrom(msg.sender, offer.buyer, listing.tokenId);

        // Then transfer funds - reentrancy possible if seller is contract
        payable(msg.sender).transfer(sellerProceeds);
        payable(feeRecipient).transfer(fee);

        emit OfferAccepted(offerId, msg.sender);
    }

    // VULNERABILITY 6: Unvalidated NFT contract
    function createListing(
        address nftContract,
        uint256 tokenId,
        uint256 price,
        uint256 duration
    ) external returns (uint256) {
        // VULNERABLE: No validation that nftContract is actually an ERC721
        // Malicious contract could be used

        // Also no check for approval
        require(price > 0, "Price must be > 0");

        return _createListing(
            msg.sender,
            nftContract,
            tokenId,
            price,
            block.timestamp + duration
        );
    }

    // VULNERABILITY 7: Offer without escrow
    function makeOffer(uint256 listingId, uint256 duration) external payable returns (uint256) {
        require(msg.value > 0, "Offer must be > 0");
        require(listings[listingId].active, "Listing not active");

        // VULNERABLE: Funds are held in contract without proper accounting
        // If offer expires, withdrawal mechanism is needed

        uint256 offerId = offerCounter++;
        offers[offerId] = Offer({
            buyer: msg.sender,
            listingId: listingId,
            amount: msg.value,
            expirationTime: block.timestamp + duration,
            active: true
        });

        emit OfferMade(offerId, msg.sender, listingId, msg.value);
        return offerId;
    }

    // VULNERABILITY 8: Withdrawal without proper checks
    function withdrawOffer(uint256 offerId) external {
        Offer storage offer = offers[offerId];
        require(offer.buyer == msg.sender, "Not offer maker");
        // VULNERABLE: Missing check if offer is still active
        // Double withdrawal possible

        uint256 amount = offer.amount;
        offer.amount = 0; // Should also set active = false

        payable(msg.sender).transfer(amount);
    }

    // VULNERABILITY 9: Centralization risk - owner can change fees
    function setFee(uint256 newFee) external {
        require(msg.sender == owner, "Not owner");
        // VULNERABLE: No upper limit on fee
        // Owner could set 100% fee
        platformFee = newFee;
    }

    // VULNERABILITY 10: Unsafe ownership transfer
    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "Not owner");
        // VULNERABLE: No two-step transfer, no zero address check
        owner = newOwner;
    }

    // Internal functions
    function _createListing(
        address seller,
        address nftContract,
        uint256 tokenId,
        uint256 price,
        uint256 expirationTime
    ) internal returns (uint256) {
        uint256 listingId = listingCounter++;
        listings[listingId] = Listing({
            seller: seller,
            nftContract: nftContract,
            tokenId: tokenId,
            price: price,
            expirationTime: expirationTime,
            active: true
        });

        emit Listed(listingId, seller, nftContract, tokenId, price);
        return listingId;
    }

    // Simple signature recovery (simplified for demo)
    function recoverSigner(bytes32 messageHash, bytes memory signature) internal pure returns (address) {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) {
            v += 27;
        }

        return ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)), v, r, s);
    }

    // Allow contract to receive ETH
    receive() external payable {}
}
