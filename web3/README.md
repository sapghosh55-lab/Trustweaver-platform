# TrustWeaver Web3 • On-Chain Threat Registry

Verifiable, transparent, and immutable on-chain threat intelligence registry deployed on **Polygon Amoy** and **Ethereum Sepolia** testnets.

## Smart Contract: `ThreatRegistry.sol`

- **Struct `ThreatReport`**:
  - `url`: The target malicious or phishing URL.
  - `score`: Threat severity score (`0 - 100`).
  - `timestamp`: Block timestamp when verified.
  - `ipfsHash`: IPFS CID containing the complete AI forensic telemetry & MITRE ATT&CK report.
  - `reporter`: Address of the authorized oracle that signed the report.
- **Event `ThreatLogged(string url, uint8 score, string ipfsHash)`**:
  - Emitted whenever a verified threat is recorded on-chain.
- **Access Control**:
  - `logThreat(...)` is restricted to authorized oracles and admin (such as the TrustWeaver FastAPI backend).
- **Public Query Methods**:
  - `isThreat(string url)`: Returns boolean indicating whether a URL is registered.
  - `getThreat(string url)`: Returns the complete `ThreatReport` struct.
  - `getTotalThreats()`: Returns total count of on-chain threat reports.
  - `getReportedUrls(uint256 offset, uint256 limit)`: Paginated query of reported URLs.

## Setup & Deployment

### 1. Install Dependencies
```bash
npm install
```

### 2. Configure Environment
Copy `.env.example` to `.env` and provide your deployer private key:
```bash
cp .env.example .env
```

### 3. Compile Contracts
```bash
npm run compile
```

### 4. Run Test Suite
```bash
npm run test
```

### 5. Deploy to Polygon Amoy Testnet
```bash
npm run deploy:amoy
```

### 6. Deploy to Ethereum Sepolia Testnet
```bash
npm run deploy:sepolia
```

