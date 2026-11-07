# TrustWeaver Shield Browser Extension

Manifest V3 real-time web trust scoring, phishing interceptor, and cryptographic validation extension for Chrome and Edge.

## Features

- **Pre-emptive Threat Blocker:** Automatically captures the active tab URL, sends a request to the Hackmatrix backend (`/scan`), and evaluates the digital trust posture.
- **Aggressive Red Full-Screen Warning Overlay:** If a critical threat is returned (e.g. Broken certificate trust chain, eMudhra compliance failures, credential harvesting, brand impersonation), `content.js` aggressively injects a full-screen red security barrier into the DOM preventing user interaction.
- **Dynamic Action Badge:** Changes color and displays letter grades (`A`, `B`, `C`, `D`, `F`) directly on the extension icon.
- **Mini Trust Score HUD Popup:** Displays an interactive SVG trust score gauge, component breakdown, and critical flags upon clicking the extension icon.

## Installation in Chrome / Edge

1. Open `chrome://extensions/` (or `edge://extensions/`).
2. Toggle on **Developer mode** in the top-right corner.
3. Click **Load unpacked**.
4. Select this `extension/` directory.
5. Ensure the Hackmatrix FastAPI backend is running on `http://localhost:8000`.
