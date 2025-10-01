// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DocumentVerification
 * @notice Register document fingerprints on-chain, with optional cryptographic signatures
 *         so verifiers can confirm the issuer identity (the wallet that signed the record).
 *
 * HASHING CONVENTION (off-chain)
 * ------------------------------
 *   docHash = keccak256( sha256(fileBytes) )   // 32 bytes
 *
 * SIGNATURE CONVENTION (EIP-191 / "personal_sign")
 * ------------------------------------------------
 * We bind the signature to the document, subject, this contract, and the chain:
 *
 *   REGISTER_MESSAGE_TYPEHASH = keccak256(
 *     "Register(bytes32 hash,address subject,address verifyingContract,uint256 chainId)"
 *   );
 *
 *   digest = keccak256(abi.encodePacked(
 *     REGISTER_MESSAGE_TYPEHASH,
 *     hash,
 *     subject,
 *     address(this),
 *     block.chainid
 *   ));
 *
 * The EIP-191 signed message is: toEthSignedMessageHash(digest)
 * and we recover its signer with ECDSA.recover(...).
 *
 * Why encodePacked? All fields here are fixed-size types; packed encoding is safe and mirrors
 * typical client-side `web3.solidityKeccak` usage. (If you prefer EIP-712 later, we can swap in cleanly.)
 */

import {AccessControl}      from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable}           from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard}    from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {ECDSA}              from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils}   from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract DocumentVerification is AccessControl, Pausable, ReentrancyGuard{
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // ---- Roles ----
    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    // ---- Storage ----
    struct Record{
        address issuer;     // Recovered signer (or msg.sender for unsigned path)
        address subject;    // Optional subject/owner; zero if N/A
        uint64 issuedAt;    // Block timestamp
        bool revoked;       // Revocation Flag
    }

    mapping(bytes32=>Record) private _records; // docHash => Record

    // ---- Errors (cheaper than revert strings) ----
    error ZeroHash();
    error AlreadyRegistered(bytes32 hash);
    error NotRegistered(bytes32 hash);
    error AlreadyRevoked(bytes32 hash);
    error NotIssuer();      // Caller lacks issuer/admin authority
    error BadSignature();   // SIgnature failed recovery

    // ---- Events ----
    event DocumentRegistered(bytes32 indexed hash, address indexed issuer, address indexed subject, string uriHint);
    event DocumentRegisteredSigned(bytes32 indexed hash, address indexed issuer, address indexed subject, string uriHint, bytes signature);
    event DocumentRevoked(bytes32 indexed hash, address indexed revoker, string reason);

    //Typehash for domain-bound message (see header)
    bytes32 private constant REGISTER_MESSAGE_TYPEHASH =
        keccak256("Register(bytes32 hash, address subject, address verifyingContract, uint256 chainId)");

    /// @param admin initial admin; received DEFAULT_ADMIN_ROLE, PAUSER_ROLE, ISSUER_ROLE
    constructor(address admin){
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(ISSUER_ROLE, admin);
    }

    // ---- Unsigned path (direct issuer) ----
    function register(bytes32 hash, address subject, string calldata uriHint)
        external
        whenNotPaused
        onlyRole(ISSUER_ROLE)
    {
        if(hash==bytes32(0)) revert ZeroHash();
        if(_records[hash].issuer!=address(0)) revert AlreadyRegistered(hash);

        _records[hash] = Record({
            issuer: msg.sender,
            subject: subject,
            issuedAt: uint64(block.timestamp),
            revoked: false
        });

        emit DocumentRegistered(hash, msg.sender, subject, uriHint);
    }

    // ---- Signed path (relayer) ----
    function registerSigned(bytes32 hash, address subject, string calldata uriHint, bytes calldata signature)
        external
        whenNotPaused
        nonReentrant
    {
        if(hash==bytes32(0)) revert ZeroHash();
        if(_records[hash].issuer!=address(0)) revert AlreadyRegistered(hash);

        // Domain-bound digest (fixed-size fields -> encodePacked is safe)
        bytes32 digest = keccak256(abi.encodePacked(
            REGISTER_MESSAGE_TYPEHASH,
            hash,
            subject,
            address(this),
            block.chainid
        ));

        bytes32 ethSigned = digest.toEthSignedMessageHash();
        address signer = ECDSA.recover(ethSigned, signature);

        if(signer==address(0)) revert BadSignature();
        if(!hasRole(ISSUER_ROLE, signer)) revert NotIssuer();

        _records[hash] = Record({
            issuer: signer,
            subject: subject,
            issuedAt: uint64(block.timestamp),
            revoked: false
        });

        // Emit signature for off-chain auditing/re-verification later
        emit DocumentRegisteredSigned(hash, signer, subject, uriHint, signature);
    }

    // ---- Revocation ----
    function revoke(bytes32 hash, string calldata reason) external whenNotPaused{
        Record storage r = _records[hash];
        if(r.issuer==address(0)) revert NotRegistered(hash);
        if(r.revoked) revert AlreadyRevoked(hash);
        if(msg.sender!=r.issuer && !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) revert NotIssuer();

        r.revoked = true;
        emit DocumentRevoked(hash, msg.sender, reason);
    }

    // ---- Views ----
    function get(bytes32 hash) external view returns (Record memory){
        return _records[hash];
    }

    function isRegistered(bytes32 hash) external view returns (bool){
        return _records[hash].issuer != address(0);
    }

    /// Convenience for clients/tests: returns the pre-EIP-191 digest for (hash, subject)
    function computeDigest(bytes32 hash, address subject) external view returns (bytes32){
        return keccak256(abi.encodePacked(
            REGISTER_MESSAGE_TYPEHASH,
            hash,
            subject,
            address(this),
            block.chainid
        ));
    }

    // ---- Admin ----
    function pause() external onlyRole(PAUSER_ROLE){
        _pause();
    }
    function unpause() external onlyRole(PAUSER_ROLE){
        _unpause();
    }
}