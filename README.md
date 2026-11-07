# TrustWeaver / Hackmatrix Platform

A cyber threat intelligence, web trust validation, and security auditing platform featuring:
- **Dual-Tier AI Routing**: Sentence Transformers dynamically route tasks between local Ollama Gemma 2 (fast privacy-preserving heuristics) and Groq Llama 3.3 70B (deep forensic reasoning).
- **Core Security Modules**: Real-time DOM phishing & brand impersonation analysis, SSL/TLS certificate chain auditing (detecting compromised CAs including the eMudhra TLS incident), and HTTP security headers/version exposure scanning.
- **Concurrent API**: Fast, parallel execution via FastAPI `/scan` generating unified Digital Trust Score reports (0-100).
- **Modern Next.js Frontend**: Accessible landing page with real-time audit search bar, visual `TrustScoreRing`, detailed `CertDetails` chain inspection, and full forensic report dashboard.
- **Manifest V3 Browser Extension**: Pre-emptively warns users and aggressively injects full-screen red blocking overlays when critical threats are encountered.

---

## Architecture

```text
trustweaver-platform/
├── backend/                       # FastAPI Service & AI Engines
│   ├── app/
│   │   ├── ai/
│   │   │   ├── local_gemma.py     # Local Ollama Gemma 2 heuristics (URL classification)
│   │   │   ├── cloud_llama.py     # Groq API Llama 3.3 70B deep reasoning (JS deobfuscation & threat synthesis)
│   │   │   └── semantic_router.py # Sentence Transformers cosine similarity router
│   │   ├── services/
│   │   │   ├── phishing_analyzer.py # Credential harvesting & brand spoofing
│   │   │   ├── cert_validator.py    # SSL/TLS validation & eMudhra CA audit
│   │   │   ├── vuln_scanner.py      # Security headers (HSTS, CSP) & version leaks
│   │   │   └── threat_intel.py      # Aggregator & Digital Trust Score synthesis
│   │   ├── api/
│   │   │   ├── routes.py          # Concurrent POST /scan orchestrator
│   │   │   └── router.py          # Detailed REST endpoints
│   │   └── main.py                # FastAPI entrypoint
│   ├── requirements.txt
│   └── .env.example
│
├── frontend/                      # Next.js 16 + TypeScript + Tailwind CSS
│   ├── src/
│   │   ├── components/
│   │   │   ├── TrustScoreRing.tsx # Dynamic SVG circular trust score gauge
│   │   │   └── CertDetails.tsx    # Certificate chain & compromised CA audit UI
│   │   └── app/
│   │       ├── page.tsx           # Accessible landing page with prominent search
│   │       └── dashboard/page.tsx # Detailed forensic intelligence report
│   ├── package.json
│   └── tsconfig.json
│
├── web3/                          # Hardhat Smart Contracts (Polygon Amoy & Sepolia)
│   ├── contracts/
│   │   └── ThreatRegistry.sol     # On-chain threat reports & oracle access control
│   ├── scripts/
│   │   └── deploy.js              # Testnet deployment script
│   ├── test/
│   │   └── ThreatRegistry.test.js # Hardhat test suite (9 passing tests)
│   ├── hardhat.config.js
│   ├── package.json
│   └── .env.example
│
└── extension/                     # Manifest V3 Chrome/Edge Extension
    ├── manifest.json              # activeTab, scripting, <all_urls>
    ├── background.js              # Tab monitor, /scan fetcher, & badge controller
    ├── content.js                 # Aggressive full-screen red warning overlay
    ├── popup.html                 # Mini Trust Score HUD
    ├── popup.css
    └── popup.js
```

---

## Quick Start

### 1. Backend Service
```bash
cd backend
# Activate virtual environment
.\venv\Scripts\activate       # Windows
# source venv/bin/activate    # Linux/macOS

pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
API docs available at: `http://localhost:8000/docs`

### 2. Frontend Web App
```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:3000` in your browser.

### 3. Web3 Threat Registry (Polygon Amoy & Sepolia)
```bash
cd web3
npm install
npm test
npm run deploy:amoy      # Deploy to Polygon Amoy Testnet
npm run deploy:sepolia   # Deploy to Ethereum Sepolia Testnet
```

### 4. Browser Extension
1. Open `chrome://extensions/` or `edge://extensions/`.
2. Enable **Developer mode**.
3. Click **Load unpacked** and select the `extension/` directory.
