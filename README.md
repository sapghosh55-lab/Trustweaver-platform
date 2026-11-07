# TrustWeaver Platform

A unified multi-component platform comprising a modern Next.js frontend, a FastAPI backend with AI capabilities, and a browser extension.

## Project Structure

```text
trustweaver-platform/
├── frontend/             # Next.js (TypeScript + Tailwind CSS)
│   ├── src/
│   │   └── app/
│   ├── public/
│   ├── package.json
│   ├── tsconfig.json
│   └── ...
├── backend/              # FastAPI Application & AI Services
│   ├── venv/             # Python Virtual Environment
│   ├── requirements.txt  # Python Dependencies
│   └── app/
│       ├── api/          # Route handlers & endpoints
│       ├── services/     # Core business logic & integrations
│       ├── ai/           # AI pipelines & embedding models
│       └── main.py       # FastAPI entrypoint
└── extension/            # Browser Extension
    └── README.md
```

## Getting Started

### 1. Frontend
```bash
cd frontend
npm run dev
```

### 2. Backend
Activate the virtual environment and install dependencies:
```bash
cd backend
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
# source venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload
```
