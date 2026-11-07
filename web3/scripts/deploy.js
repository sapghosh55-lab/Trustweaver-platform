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
  console.log(`Deployer Balance       : ${hre.ethers.formatEther(balance)} ETH`);
  console.log("--------------------------------------------------");

  // Deploy ThreatRegistry contract
  console.log("Deploying ThreatRegistry contract...");
  const ThreatRegistry = await hre.ethers.getContractFactory("ThreatRegistry");
  const registry = await ThreatRegistry.deploy();

  await registry.waitForDeployment();
  const contractAddress = await registry.getAddress();

  console.log(" ThreatRegistry successfully deployed!");
  console.log(`Contract Address       : ${contractAddress}`);

  // Fetch the compiled ABI from Hardhat artifacts
  const artifact = await hre.artifacts.readArtifact("ThreatRegistry");
  const abi = artifact.abi;

  // 1. Write Contract Address and compiled ABI to backend/app/core/contract_abi.json
  const backendCoreDir = path.join(__dirname, "..", "..", "backend", "app", "core");
  if (!fs.existsSync(backendCoreDir)) {
    fs.mkdirSync(backendCoreDir, { recursive: true });
  }

  const contractAbiData = {
    contractName: "ThreatRegistry",
    contractAddress: contractAddress,
    network: network.name || "localhost",
    chainId: network.chainId.toString(),
    deployedAt: new Date().toISOString(),
    deployer: deployer.address,
    abi: abi,
  };

  const targetAbiPath = path.join(backendCoreDir, "contract_abi.json");
  fs.writeFileSync(targetAbiPath, JSON.stringify(contractAbiData, null, 2), "utf-8");
  console.log(` Contract ABI & Address saved to: ${targetAbiPath}`);

  // Also ensure backend/app/core/__init__.py exists
  const initPyPath = path.join(backendCoreDir, "__init__.py");
  if (!fs.existsSync(initPyPath)) {
    fs.writeFileSync(initPyPath, "# core package\n", "utf-8");
  }

  // 2. Persist deployment metadata under web3/deployments
  const deploymentsDir = path.join(__dirname, "..", "deployments");
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }

  fs.writeFileSync(
    path.join(deploymentsDir, `${network.name || "localhost"}-${network.chainId}.json`),
    JSON.stringify(contractAbiData, null, 2),
    "utf-8"
  );

  console.log("--------------------------------------------------");
  console.log("DEPLOYMENT COMPLETE");
  console.log(`FastAPI backend configuration updated via contract_abi.json`);
  console.log("==================================================");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("Deployment failed:", error);
    process.exit(1);
  });
