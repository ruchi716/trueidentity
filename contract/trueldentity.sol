// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title TrueIdentity
 * @dev A decentralized identity verification system
 */
contract TrueIdentity {
    
    struct Identity {
        string name;
        uint256 dateOfBirth;
        string documentHash; // IPFS hash or encrypted document reference
        bool isVerified;
        address verifier;
        uint256 verificationDate;
    }
    
    mapping(address => Identity) private identities;
    mapping(address => bool) public isVerifier;
    address public owner;
    
    event IdentityRegistered(address indexed user, string name, uint256 timestamp);
    event IdentityVerified(address indexed user, address indexed verifier, uint256 timestamp);
    event VerifierAdded(address indexed verifier, uint256 timestamp);
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can perform this action");
        _;
    }
    
    modifier onlyVerifier() {
        require(isVerifier[msg.sender], "Only authorized verifiers can perform this action");
        _;
    }
    
    constructor() {
        owner = msg.sender;
        isVerifier[msg.sender] = true; // Owner is default verifier
    }
    
    /**
     * @dev Register a new identity on the blockchain
     * @param _name Full name of the user
     * @param _dateOfBirth Date of birth in Unix timestamp
     * @param _documentHash Hash of identity documents stored off-chain
     */
    function registerIdentity(
        string memory _name,
        uint256 _dateOfBirth,
        string memory _documentHash
    ) public {
        require(bytes(identities[msg.sender].name).length == 0, "Identity already registered");
        require(bytes(_name).length > 0, "Name cannot be empty");
        require(_dateOfBirth < block.timestamp, "Invalid date of birth");
        
        identities[msg.sender] = Identity({
            name: _name,
            dateOfBirth: _dateOfBirth,
            documentHash: _documentHash,
            isVerified: false,
            verifier: address(0),
            verificationDate: 0
        });
        
        emit IdentityRegistered(msg.sender, _name, block.timestamp);
    }
    
    /**
     * @dev Verify a user's identity (only authorized verifiers can call this)
     * @param _user Address of the user whose identity needs verification
     */
    function verifyIdentity(address _user) public onlyVerifier {
        require(bytes(identities[_user].name).length > 0, "Identity not registered");
        require(!identities[_user].isVerified, "Identity already verified");
        
        identities[_user].isVerified = true;
        identities[_user].verifier = msg.sender;
        identities[_user].verificationDate = block.timestamp;
        
        emit IdentityVerified(_user, msg.sender, block.timestamp);
    }
    
    /**
     * @dev Get identity details of a user
     * @param _user Address of the user
     * @return name User's name
     * @return isVerified Verification status
     * @return verifier Address of the verifier (if verified)
     */
    function getIdentity(address _user) public view returns (
        string memory name,
        bool isVerified,
        address verifier
    ) {
        Identity memory identity = identities[_user];
        return (identity.name, identity.isVerified, identity.verifier);
    }
    
    /**
     * @dev Add a new authorized verifier (only owner can call this)
     * @param _verifier Address of the new verifier
     */
    function addVerifier(address _verifier) public onlyOwner {
        require(_verifier != address(0), "Invalid verifier address");
        require(!isVerifier[_verifier], "Already a verifier");
        
        isVerifier[_verifier] = true;
        emit VerifierAdded(_verifier, block.timestamp);
    }
    
    /**
     * @dev Check if a user's identity is verified
     * @param _user Address of the user
     * @return bool Verification status
     */
    function isIdentityVerified(address _user) public view returns (bool) {
        return identities[_user].isVerified;
    }
}
