// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import "@openzeppelin/contracts@4.8.1/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts@4.8.1/access/Ownable.sol";

contract FairFundingToken is ERC721, Ownable {
    constructor() ERC721("FairFundingToken", "FFT") {}

    /**
     * @notice We expose `mint` and not `safeMint` here to avoid
     *         potential DoS issue when settling an auction.
     * @param to address of the token receiver
     * @param tokenId id to be minted
     */
    function mint(address to, uint256 tokenId) public onlyOwner {
        _mint(to, tokenId);
    }
}
