const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("ThreatRegistry Contract", function () {
  let ThreatRegistry, registry, owner, oracle, user;

  beforeEach(async function () {
    [owner, oracle, user] = await ethers.getSigners();

    ThreatRegistry = await ethers.getContractFactory("ThreatRegistry");
    registry = await ThreatRegistry.deploy();
    await registry.waitForDeployment();
  });

  describe("Deployment & Initial State", function () {
    it("Should set deployer as the owner", async function () {
      expect(await registry.owner()).to.equal(owner.address);
    });

    it("Should authorize deployer as initial oracle", async function () {
      expect(await registry.authorizedOracles(owner.address)).to.be.true;
    });

    it("Should have 0 initial threats", async function () {
      expect(await registry.getTotalThreats()).to.equal(0);
    });
  });

  describe("Oracle Management", function () {
    it("Should allow owner to authorize a new oracle", async function () {
      await expect(registry.setOracle(oracle.address, true))
        .to.emit(registry, "OracleAuthorizationChanged")
        .withArgs(oracle.address, true);

      expect(await registry.authorizedOracles(oracle.address)).to.be.true;
    });

    it("Should revert if non-owner attempts to authorize oracle", async function () {
      await expect(
        registry.connect(user).setOracle(oracle.address, true)
      ).to.be.revertedWith("ThreatRegistry: caller is not the owner");
    });
  });

  describe("Threat Logging", function () {
    const maliciousUrl = "https://phishing-portal-fake-login.xyz/auth";
    const threatScore = 95;
    const ipfsHash = "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco";

    it("Should allow authorized oracle to log a threat", async function () {
      // Authorize oracle
      await registry.setOracle(oracle.address, true);

      // Log threat
      await expect(
        registry.connect(oracle).logThreat(maliciousUrl, threatScore, ipfsHash)
      )
        .to.emit(registry, "ThreatLogged")
        .withArgs(maliciousUrl, maliciousUrl, threatScore, ipfsHash, oracle.address, await ethers.provider.getBlock("latest").then(b => b.timestamp + 1));

      // Verify threat existence and details
      expect(await registry.isThreat(maliciousUrl)).to.be.true;

      const report = await registry.getThreat(maliciousUrl);
      expect(report.url).to.equal(maliciousUrl);
      expect(report.score).to.equal(threatScore);
      expect(report.ipfsHash).to.equal(ipfsHash);
      expect(report.reporter).to.equal(oracle.address);
      expect(report.exists).to.be.true;

      expect(await registry.getTotalThreats()).to.equal(1);
    });

    it("Should revert if unauthorized user attempts to log threat", async function () {
      await expect(
        registry.connect(user).logThreat(maliciousUrl, threatScore, ipfsHash)
      ).to.be.revertedWith("ThreatRegistry: caller is not an authorized oracle or owner");
    });

    it("Should revert if score exceeds 100", async function () {
      await expect(
        registry.logThreat(maliciousUrl, 105, ipfsHash)
      ).to.be.revertedWith("ThreatRegistry: score must be between 0 and 100");
    });

    it("Should revert if URL is empty", async function () {
      await expect(
        registry.logThreat("", threatScore, ipfsHash)
      ).to.be.revertedWith("ThreatRegistry: URL cannot be empty");
    });
  });
});

