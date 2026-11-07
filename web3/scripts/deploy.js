const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  const network = await hre.ethers.provider.getNetwork();

  console.log("==================================================");
  console.log("  TrustWeaver / Hackmatrix - ThreatRegistry Deploy");
  console.log("==================================================");
  console.log(`Deploying from account : ${deployer.address}`);
  console.log(`Network Name           : ${network.name}`);
  console.log(`Chain ID               : ${network.chainId}`);

  const balance = await hre.ethers.provider.getBalance(deployer.address);
  console.log(`Deployer Balance       : ${hre.ethers.formatEther(balance)} native currency`);
  console.log("--------------------------------------------------");

  // Deploy ThreatRegistry contract
  console.log("Deploying ThreatRegistry contract...");
  const ThreatRegistry = await hre.ethers.getContractFactory("ThreatRegistry");
  const registry = await ThreatRegistry.deploy();

  await registry.waitForDeployment();
  const contractAddress = await registry.getAddress();

  console.log(` ThreatRegistry successfully deployed!`);
  console.log(`Contract Address       : ${contractAddress}`);

  // Display explorer link based on chain ID
  if (network.chainId === 80002n) {
    console.log(`Polygon Amoy Explorer  : https://amoy.polygonscan.com/address/${contractAddress}`);
  } else if (network.chainId === 11155111n) {
    console.log(`Sepolia Etherscan      : https://sepolia.etherscan.io/address/${contractAddress}`);
  }

  // Persist deployed deployment metadata for backend integration
  const deploymentsDir = path.join(__dirname, "..", "deployments");
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }

  const deploymentData = {
    network: network.name,
    chainId: network.chainId.toString(),
    contractAddress: contractAddress,
    deployer: deployer.address,
    deployedAt: new Date().toISOString(),
  };

  fs.writeFileSync(
    path.join(deploymentsDir, `${network.name || "network"}-${network.chainId}.json`),
    JSON.stringify(deploymentData, null, 2)
  );

  console.log("--------------------------------------------------");
  console.log("NEXT STEPS:");
  console.log("1. Add to backend/.env:");
  console.log(`   THREAT_REGISTRY_CONTRACT_ADDRESS=${contractAddress}`);
  console.log("2. Authorize your FastAPI backend oracle address:");
  console.log("   await registry.setOracle('<FASTAPI_ORACLE_WALLET_ADDRESS>', true)");
  console.log("==================================================");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("Deployment failed:", error);
    process.exit(1);
  });

