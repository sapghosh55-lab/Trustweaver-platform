// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ThreatRegistry
 * @dev Transparent, decentralized, and verifiable on-chain registry for validated cyber threats.
 * Part of the TrustWeaver / Hackmatrix platform.
 * Authorized oracles (such as the FastAPI AI backend) record validated malicious URLs,
 * threat scores, and IPFS metadata hashes on-chain.
 */
contract ThreatRegistry {
    // Structure defining a validated threat intelligence record
    struct ThreatReport {
        string url;
        uint8 score;          // Digital Threat Score (0 - 100, where higher indicates greater threat)
        uint256 timestamp;    // Block timestamp when logged
        string ipfsHash;      // IPFS CID containing full AI forensic telemetry & MITRE report
        address reporter;     // Address of the authorized oracle that signed the report
        bool exists;          // Quick existence flag
    }

    // Contract admin / owner
    address public owner;

    // Authorized oracles (e.g., TrustWeaver FastAPI backend wallet)
    mapping(address => bool) public authorizedOracles;

    // Mapping of URL string to ThreatReport
    mapping(string => ThreatReport) private _reports;

    // Ordered list of reported URLs for enumeration and pagination
    string[] private _reportedUrls;

    // Events
    event ThreatLogged(string indexed urlIndexed, string url, uint8 score, string ipfsHash, address indexed oracle, uint256 timestamp);
    event OracleAuthorizationChanged(address indexed oracle, bool authorized);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "ThreatRegistry: caller is not the owner");
        _;
    }

    modifier onlyOracleOrAdmin() {
        require(
            msg.sender == owner || authorizedOracles[msg.sender],
            "ThreatRegistry: caller is not an authorized oracle or owner"
        );
        _;
    }

    /**
     * @dev Initialize contract with deployer as owner and initial oracle.
     */
    constructor() {
        owner = msg.sender;
        authorizedOracles[msg.sender] = true;
        emit OwnershipTransferred(address(0), msg.sender);
        emit OracleAuthorizationChanged(msg.sender, true);
    }

    /**
     * @notice Record a validated threat report on-chain.
     * @dev Restricted to authorized oracle or admin address.
     * @param url The malicious or suspicious target URL.
     * @param score Threat severity score from 0 (benign) to 100 (critical threat).
     * @param ipfsHash IPFS CID containing the complete forensic telemetry report.
     */
    function logThreat(
        string memory url,
        uint8 score,
        string memory ipfsHash
    ) external onlyOracleOrAdmin {
        require(bytes(url).length > 0, "ThreatRegistry: URL cannot be empty");
        require(score <= 100, "ThreatRegistry: score must be between 0 and 100");

        bool isNew = !_reports[url].exists;

        _reports[url] = ThreatReport({
            url: url,
            score: score,
            timestamp: block.timestamp,
            ipfsHash: ipfsHash,
            reporter: msg.sender,
            exists: true
        });

        if (isNew) {
            _reportedUrls.push(url);
        }

        emit ThreatLogged(url, url, score, ipfsHash, msg.sender, block.timestamp);
    }

    /**
     * @notice Check whether a URL has been registered as a validated threat.
     */
    function isThreat(string memory url) external view returns (bool) {
        return _reports[url].exists;
    }

    /**
     * @notice Retrieve the full threat report for a URL.
     */
    function getThreat(string memory url) external view returns (ThreatReport memory) {
        require(_reports[url].exists, "ThreatRegistry: URL not found in registry");
        return _reports[url];
    }

    /**
     * @notice Total number of unique threats registered.
     */
    function getTotalThreats() external view returns (uint256) {
        return _reportedUrls.length;
    }

    /**
     * @notice Get a list of reported URLs with pagination.
     */
    function getReportedUrls(uint256 offset, uint256 limit) external view returns (string[] memory) {
        uint256 total = _reportedUrls.length;
        if (offset >= total) {
            return new string[](0);
        }

        uint256 end = offset + limit;
        if (end > total) {
            end = total;
        }

        uint256 resultLength = end - offset;
        string[] memory result = new string[](resultLength);

        for (uint256 i = 0; i < resultLength; i++) {
            result[i] = _reportedUrls[offset + i];
        }

        return result;
    }

    /**
     * @notice Authorize or revoke an oracle address.
     */
    function setOracle(address oracle, bool authorized) external onlyOwner {
        require(oracle != address(0), "ThreatRegistry: invalid oracle address");
        authorizedOracles[oracle] = authorized;
        emit OracleAuthorizationChanged(oracle, authorized);
    }

    /**
     * @notice Transfer contract ownership to a new address.
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "ThreatRegistry: new owner is zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}

