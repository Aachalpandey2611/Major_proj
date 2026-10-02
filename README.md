# SentinelLoop v3 🛡️

> **AI Red-Team & Auto-Verify Platform for Chatbots**  
> Automated LLM security testing with vulnerability detection, fix recommendations, and continuous verification.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose installed
- Python 3.11+ (for helper scripts)
- OpenAI API key or Groq API key (free tier: 14,400 req/day)

### Setup Instructions

1. **Clone the repository**
   ```bash
   git clone https://github.com/Aachalpandey2611/Major_proj.git
   cd Major_proj
   ```

2. **Create your environment file**
   ```bash
   cp .env.example .env
   ```

3. **Edit `.env` and add your API key**
   ```bash
   # Open .env in your editor
   # Replace this line:
   OPENAI_API_KEY=sk-your-openai-api-key-here
   
   # With your actual key (OpenAI or Groq):
   OPENAI_API_KEY=sk-proj-xxxxx...  # OpenAI key
   # OR
   OPENAI_API_KEY=gsk_xxxxx...      # Groq API key (free tier works!)
   ```
   
   **Note:** All other values in `.env.example` are already configured correctly. You only need to change the API key.

4. **Generate secure keys** (optional but recommended for production)
   ```bash
   # Generate SECRET_KEY
   python -c "import secrets; print(secrets.token_hex(32))"
   
   # Generate TOKEN_ENCRYPTION_KEY
   python -c "import secrets; print(secrets.token_hex(32))"
   
   # Copy the output and replace the values in .env
   ```

5. **Start all services**
   ```bash
   docker-compose up -d
   ```
   
   This will start:
   - **Frontend** (React + Vite): http://localhost:5173
   - **Backend** (FastAPI): http://localhost:8001
   - **PostgreSQL** database: localhost:5433
   - **Redis**: localhost:6380
   - **Celery Worker** (for async scans)
   - **Celery Beat** (for scheduled tasks)
   - **Test Chatbot** (vulnerable): http://localhost:9000
   - **Generic LLM Target**: http://localhost:9001

6. **Wait for services to be healthy** (30-60 seconds)
   ```bash
   docker-compose ps
   ```
   All services should show "Up" and "healthy" status.

7. **Open the application**
   ```bash
   # Open in your browser:
   http://localhost:5173
   ```

8. **Register an account**
   - Click "Sign Up" on the homepage
   - Create your account (email + password)
   - Login with your credentials

---

## 🎯 Testing the Vulnerable Chatbot

The project includes a **pre-configured vulnerable chatbot** that will automatically show findings after scanning.

### Option 1: Automatic Registration (Recommended)

Run the provided registration script:

```bash
# Make sure all Docker services are running first
docker-compose ps

# Run the registration script
python register_test_bot.py
```

This script will:
1. ✅ Register the test chatbot automatically
2. ✅ Create the verification file
3. ✅ Verify ownership
4. ✅ Print the Target ID for scanning

### Option 2: Manual Registration via UI

1. **Login to SentinelLoop** (http://localhost:5173)

2. **Add a new target:**
   - Go to "Targets" page
   - Click "Add Target"
   - Fill in:
     - **Name:** `Vulnerable Test Chatbot`
     - **URL:** `http://test_chatbot:9000`
     - **Environment:** `dev`
   - Click "Create"

3. **Verify ownership:**
   - Copy the verification token from the target details
   - The verification file is **already created** in `test_chatbot/.well-known/sentinelloop-verify.txt`
   - Click "Verify" on the target
   - Status should change to "Verified" ✅

4. **Launch a scan:**
   - Click "Start Scan" on the verified target
   - The scan will run automatically (takes 2-5 minutes)

5. **View results:**
   - Go to "Dashboard" to see analytics
   - Go to "Findings" to see detected vulnerabilities
   - **Expected:** You should see **71 vulnerabilities** with various confidence scores

---

## 📊 What You'll See

### Dashboard Analytics
After scanning the vulnerable chatbot, you'll see:

- **Overall Security Score:** ~0-30% (vulnerable)
- **Average Confidence Score:** ~60-80%
- **Total Findings:** 71 vulnerabilities
- **Vulnerability Distribution:** Pie chart showing attack types
- **Confidence Distribution:** Distribution of detection confidence
- **Color-coded Security Indicators:**
  - 🔴 Red: Vulnerable (0-50% security score)
  - 🟡 Amber: Moderate (51-80% security score)
  - 🟢 Green: Secure (81-100% security score)

### Attack Types Detected
The scanner tests for 15+ attack types:
- ✅ Prompt Injection
- ✅ Jailbreak Attempts
- ✅ System Prompt Leak
- ✅ Data Leakage
- ✅ Role Override
- ✅ Context Manipulation
- ✅ API Abuse
- ✅ Tool Abuse
- ✅ Indirect Injection
- ✅ SQL Injection
- ✅ Training Data Extraction
- ✅ RAG Poisoning
- ✅ Sponge Attack
- ✅ Denial of Wallet
- ✅ Few-shot Leakage

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     User Interface (React)                   │
│           Dashboard | Targets | Scans | Findings             │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   Backend API (FastAPI)                      │
│        Auth | Targets | Scans | Findings | Reports          │
└─────┬───────────────────────┬───────────────────────────────┘
      │                       │
      ▼                       ▼
┌─────────────────┐    ┌──────────────────────────────────────┐
│  PostgreSQL DB  │    │        Celery Workers                │
│  (persistent)   │    │  ┌────────────────────────────────┐  │
└─────────────────┘    │  │   Attack Engine                │  │
                       │  │   - Generate adversarial prompts│  │
┌─────────────────┐    │  │   - Send to target chatbot     │  │
│   Redis Cache   │    │  └────────────────────────────────┘  │
│  (task queue)   │    │  ┌────────────────────────────────┐  │
└─────────────────┘    │  │   Detection Engine             │  │
                       │  │   - Rule-based detector        │  │
                       │  │   - ML classifier (PromptGuard)│  │
                       │  │   - LLM judge (GPT-4o-mini)    │  │
                       │  └────────────────────────────────┘  │
                       │  ┌────────────────────────────────┐  │
                       │  │   Fix Engine                   │  │
                       │  │   - Map vulnerability to fix   │  │
                       │  │   - Generate reports           │  │
                       │  └────────────────────────────────┘  │
                       └──────────────────────────────────────┘
```

---

## 🛠️ Common Commands

### View logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f backend
docker-compose logs -f celery_worker
docker-compose logs -f frontend
```

### Restart services
```bash
# All services
docker-compose restart

# Specific service
docker-compose restart backend
```

### Stop all services
```bash
docker-compose down
```

### Reset database (clean slate)
```bash
docker-compose down -v
docker-compose up -d
```

### Check service health
```bash
docker-compose ps
```

---

## 🐛 Troubleshooting

### Services not starting?

1. **Check Docker is running:**
   ```bash
   docker --version
   docker-compose --version
   ```

2. **Check port conflicts:**
   ```bash
   # Make sure these ports are free:
   # 5173 (frontend), 8001 (backend), 5433 (postgres), 6380 (redis)
   # 9000 (test_chatbot), 9001 (generic_llm_target)
   ```

3. **Check logs:**
   ```bash
   docker-compose logs backend
   docker-compose logs postgres
   ```

### Database connection errors?

```bash
# Wait for postgres to be healthy
docker-compose ps postgres

# Should show "healthy" status
# If not, wait 30 more seconds and check again
```

### Frontend not loading?

```bash
# Check if frontend is running
docker-compose logs frontend

# Restart frontend
docker-compose restart frontend

# Clear browser cache and reload
```

### No vulnerabilities showing up?

1. **Check if scan completed:**
   - Go to "Scans" page
   - Status should be "completed"
   - If "failed", check celery_worker logs

2. **Check API key:**
   - Make sure `OPENAI_API_KEY` in `.env` is valid
   - Test with: `python test_openai.py`

3. **Check celery worker:**
   ```bash
   docker-compose logs celery_worker
   ```

### API key not working?

```bash
# Test your OpenAI/Groq key
python test_openai.py

# If using Groq (free tier):
# Key format: gsk_xxxxx...
# Rate limit: 14,400 requests/day
# Model used: llama-3.3-70b-versatile
```

---

## 📁 Project Structure

```
Major_proj/
├── backend/                    # FastAPI backend
│   ├── attack_engine/         # Attack generation & execution
│   ├── detection_engine/      # Vulnerability detection
│   ├── fix_engine/            # Fix recommendations
│   ├── dataset/               # Attack templates (15+ types)
│   ├── routers/               # API endpoints
│   ├── alembic/               # Database migrations
│   └── main.py               # FastAPI app entry
├── frontend/                  # React + Vite frontend
│   ├── src/
│   │   ├── pages/            # Dashboard, Targets, Scans, Findings
│   │   ├── components/       # Reusable UI components
│   │   └── services/         # API client
│   └── package.json
├── test_chatbot/             # Vulnerable test chatbot
│   ├── main.py              # Intentionally vulnerable LLM
│   └── .well-known/         # Verification file
├── docker-compose.yml        # Service orchestration
├── .env.example             # Environment template
└── README.md                # This file
```

---

## 🔐 Security Notes

### For Development:
- ✅ `.env` is in `.gitignore` (never commit secrets!)
- ✅ Default keys are provided for local development
- ✅ Test chatbot is intentionally vulnerable for demo

### For Production:
- 🔒 Generate new `SECRET_KEY` and `TOKEN_ENCRYPTION_KEY`
- 🔒 Use environment-specific API keys
- 🔒 Enable HTTPS/TLS
- 🔒 Use managed secrets (AWS Secrets Manager, GCP Secret Manager)
- 🔒 Change database credentials
- 🔒 Enable rate limiting
- 🔒 Review and update CORS settings

---

## 📚 Documentation

- **Full Documentation:** [SentinelLoop_Documentation.md](SentinelLoop_Documentation.md)
- **Build Plan:** [MASTER_BUILD_PLAN.md](MASTER_BUILD_PLAN.md)
- **API Reference:** http://localhost:8001/docs (when running)

---

## 🤝 Contributing

This is a university project by:
- **Aachal Pandey** ([@Aachalpandey2611](https://github.com/Aachalpandey2611))
- **Prachi Singh**
- **Pratik**
- **Roshan**

### Team Contributions:
- **Aachal:** Attack Engine, Frontend Dashboard
- **Prachi:** Detection Engine, ML Classifier
- **Pratik:** Fix Engine, Reports
- **Roshan:** Auto-Retest, DevOps

---

## 📝 License

MIT License - see LICENSE file for details

---

## 🎓 Research Foundation

Based on:
- OWASP LLM Top 10 (2024)
- EU AI Act compliance requirements
- NIST AI Risk Management Framework
- Academic research on adversarial AI attacks

---

## 🚀 Next Steps

After successfully running the project:

1. ✅ Scan the vulnerable test chatbot
2. ✅ Review findings on the Dashboard
3. ✅ Check fix recommendations
4. ✅ Try scanning your own chatbot
5. ✅ Explore the API docs: http://localhost:8001/docs

---

## 💡 Support

If you encounter issues:
1. Check the [Troubleshooting](#-troubleshooting) section
2. Review service logs: `docker-compose logs <service>`
3. Create an issue on GitHub
4. Check if all services are healthy: `docker-compose ps`

---

**Built with ❤️ by Team SentinelLoop**
