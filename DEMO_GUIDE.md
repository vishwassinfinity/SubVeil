# 🎬 SubVeil - Live Demo Guide

## How to Show the Working System

This guide will walk you through demonstrating SubVeil's complete functionality.

---

## 🚀 Quick Start (5 Minutes)

### Step 1: Start Both Servers

Open **two terminal windows**:

**Terminal 1 - Backend:**
```bash
cd /Users/vishwassinfinity/Desktop/Programming/Projects/SubVeil/backend
npm run dev
```

You should see:
```
╔═══════════════════════════════════════════════════════╗
║   🛡️  SubVeil API Server                              ║
║   Status: Running                                     ║
║   Port: 3000                                        ║
╚═══════════════════════════════════════════════════════╝
```

**Terminal 2 - Frontend:**
```bash
cd /Users/vishwassinfinity/Desktop/Programming/Projects/SubVeil/frontend
npm run dev
```

You should see:
```
  VITE v5.x.x  ready in xxx ms

  ➜  Local:   http://localhost:5173/
```

### Step 2: Open the Application

Open your browser and go to: **http://localhost:5173/**

---

## 🎯 Complete Demo Flow (15 Minutes)

### Demo 1: Dashboard Overview

1. **Navigate to Dashboard** (default page)
   - Shows statistics cards (Total Scans, Findings, etc.)
   - View recent activity chart
   - See severity distribution pie chart

**What to highlight:**
- "This dashboard pulls real-time data from our backend API"
- "Notice the clean UI with dark/light mode toggle"

---

### Demo 2: Create and Run a Real Scan

1. **Navigate to Scans** (click "Scans" in sidebar)

2. **Click "Add Domain" button**

3. **Enter a domain to scan:**
   - **Safe option**: `github.com` (has subdomains but is safe to scan)
   - **Other options**: `netlify.com`, `vercel.com`, `heroku.com`

4. **Click "Add Domain" to start the scan**

**What happens:**
```
Frontend → POST /api/scans → Backend
Backend → Creates scan in database
Backend → Starts enumeration automatically
Backend → Returns scan details to Frontend
```

5. **Watch the progress:**
   - Status shows "Running"
   - Progress bar updates in real-time
   - Subdomains found counter increases
   - Scan duration updates

**Narration:**
> "The system is now enumerating subdomains using three methods:
> 1. Brute force against 70+ common subdomain names
> 2. Certificate Transparency logs from crt.sh
> 3. Keyword-based permutations
> 
> For each subdomain found, it performs DNS lookups to detect
> dangling CNAME records, then fingerprints HTTP responses
> against 20 cloud provider signatures."

6. **Wait for completion** (2-10 minutes depending on domain)
   - Status changes to "Completed"
   - Shows final counts

---

### Demo 3: View Findings

1. **Navigate to Findings** (click "Findings" in sidebar)

2. **View the detected vulnerabilities:**
   - Each finding shows:
     - Subdomain
     - Provider (e.g., AWS S3, GitHub Pages)
     - Severity badge (Critical/High/Medium/Low)
     - Confidence score

3. **Click "View Details" on a finding:**
   - See full evidence:
     - CNAME record
     - HTTP status code
     - Response fingerprints matched
     - Detection timestamp
   - View remediation steps

**What to highlight:**
> "Each finding includes concrete evidence from DNS and HTTP
> responses. The confidence score is calculated based on how
> many fingerprints matched the provider's signature."

---

### Demo 4: Export Findings

1. **On Findings page, click "Export"**

2. **Choose format:**
   - JSON (for programmatic use)
   - CSV (for spreadsheets)

3. **File downloads automatically**

**Show the exported file:**
```bash
# View JSON export
cat ~/Downloads/findings-export-*.json

# View CSV export
open ~/Downloads/findings-export-*.csv
```

---

### Demo 5: Manage Providers

1. **Navigate to Providers** (click "Providers" in sidebar)

2. **View the 20 pre-configured providers:**
   - GitHub Pages
   - AWS S3
   - Heroku
   - Azure
   - And 16 more...

3. **Click "View Details" on a provider:**
   - See CNAME patterns
   - View fingerprints (HTTP response indicators)
   - See detection count

4. **Add a custom provider** (optional):
   - Click "Add Provider"
   - Fill in details:
     - Name: `Custom Service`
     - CNAME Pattern: `custom.service.com`
     - Fingerprints: `NoSuchBucket, Not Found`
   - Click "Save"

**What to highlight:**
> "The system is extensible - you can add any cloud provider
> or service by defining its CNAME pattern and HTTP fingerprints."

---

### Demo 6: Advanced Features

#### Pause/Resume a Scan

1. Go back to **Scans** page
2. Start a new scan with a large domain
3. Click **"Pause"** button while running
4. Status changes to "Paused"
5. Click **"Resume"** to continue
6. Scan picks up where it left off

#### Delete a Scan

1. Click **"Delete"** button on any scan
2. Confirmation dialog appears
3. Confirm deletion
4. Scan and all findings removed

#### Theme Toggle

1. Click the **moon/sun icon** in top right
2. Switch between dark and light modes
3. Show how the entire UI adapts

---

## 🧪 Backend API Demo (For Technical Audience)

Open a third terminal and demonstrate the REST API directly:

### Test 1: Health Check
```bash
curl http://localhost:3000/health
```

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2025-11-21T..."
}
```

### Test 2: Get Statistics
```bash
curl http://localhost:3000/api/stats | jq
```

**Response:**
```json
{
  "totalScans": 5,
  "totalFindings": 12,
  "criticalFindings": 3,
  "totalSubdomains": 145,
  "activeScans": 1,
  "recentActivity": [...]
}
```

### Test 3: Create a Scan Programmatically
```bash
curl -X POST http://localhost:3000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}' | jq
```

**Response:**
```json
{
  "id": "clp...",
  "domain": "example.com",
  "status": "running",
  "progress": 0,
  "startTime": "2025-11-21T..."
}
```

### Test 4: Get Scan Details
```bash
# Replace SCAN_ID with actual ID from previous response
curl http://localhost:3000/api/scans/SCAN_ID | jq
```

### Test 5: List All Findings
```bash
curl http://localhost:3000/api/findings | jq
```

### Test 6: Export Findings as JSON
```bash
curl http://localhost:3000/api/findings/export?format=json | jq > findings.json
```

### Test 7: Export Findings as CSV
```bash
curl http://localhost:3000/api/findings/export?format=csv > findings.csv
cat findings.csv
```

---

## 📊 Database Demo (Show Real Data)

### View the SQLite Database

```bash
cd /Users/vishwassinfinity/Desktop/Programming/Projects/SubVeil/backend

# Install SQLite CLI if needed
# brew install sqlite3

# Open database
sqlite3 dev.db
```

**SQL Queries to demonstrate:**

```sql
-- View all scans
SELECT id, domain, status, progress, subdomainsFound, vulnerableCount 
FROM Scan;

-- View all findings with severity
SELECT subdomain, provider, severity, confidence, resolved 
FROM Finding 
ORDER BY severity DESC;

-- Count findings by severity
SELECT severity, COUNT(*) as count 
FROM Finding 
GROUP BY severity;

-- View all providers
SELECT name, cnamePattern, detectionsCount 
FROM Provider 
WHERE active = 1;

-- Get scan statistics
SELECT 
  COUNT(*) as total_scans,
  SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
  SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) as running,
  SUM(subdomainsFound) as total_subdomains,
  SUM(vulnerableCount) as total_vulnerabilities
FROM Scan;

-- Exit
.quit
```

---

## 🎥 Video Demo Script (If Recording)

### Introduction (30 seconds)
> "Hi, I'm demonstrating SubVeil, a subdomain takeover detection system.
> It automatically discovers subdomains, analyzes DNS records, and detects
> vulnerabilities across 20+ cloud providers. Let's see it in action."

### Setup (15 seconds)
> "I have both the backend API running on port 3000 and the React frontend
> on port 5173. The system uses SQLite for persistence and Prisma ORM."

### Creating a Scan (1 minute)
> "Let's scan github.com. I'll enter the domain and click Add Domain.
> The system immediately starts three enumeration techniques:
> brute force, certificate transparency, and permutations.
> 
> Watch the progress bar - it's discovering subdomains in real-time.
> For each subdomain, it performs DNS lookups to find dangling CNAMEs,
> then fingerprints the HTTP responses."

### Viewing Results (1 minute)
> "The scan is complete. Let's check the Findings page.
> Here we can see any vulnerabilities detected, with severity levels
> and confidence scores.
> 
> I can click View Details to see the full evidence - the CNAME record,
> HTTP status code, and which fingerprints matched.
> 
> I can also export all findings as JSON or CSV for reporting."

### Provider Management (30 seconds)
> "In the Providers section, we have 20 pre-configured cloud providers
> like AWS S3, GitHub Pages, Heroku, and more. Each has specific CNAME
> patterns and HTTP fingerprints. You can add custom providers too."

### API Demo (30 seconds)
> "The entire system is API-driven. Here I'm making a direct API call
> to create a scan programmatically. You can integrate SubVeil into
> your CI/CD pipeline or security workflows."

### Conclusion (15 seconds)
> "SubVeil provides automated, continuous subdomain takeover detection
> with a beautiful UI, REST API, and real-time scanning. Thanks for watching!"

---

## 🎨 Screenshots to Capture

1. **Dashboard** - Full view showing statistics and charts
2. **Scans Page** - List of scans with running status
3. **Scan Progress** - Active scan with progress bar
4. **Findings List** - Multiple findings with severity badges
5. **Finding Details** - Expanded finding with evidence
6. **Providers Page** - Grid of provider cards
7. **Provider Details** - Expanded provider with fingerprints
8. **Export Dialog** - Showing JSON/CSV options
9. **Dark Mode** - Same page in dark theme
10. **API Response** - Terminal showing curl output

---

## 🏆 Key Features to Highlight

### Technical Features
✅ **Real DNS Resolution** - Not mocked, actual lookups
✅ **HTTP Fingerprinting** - Fetches and analyzes responses
✅ **Certificate Transparency** - Queries crt.sh API
✅ **Concurrent Processing** - 10 DNS, 5 HTTP at a time
✅ **Database Persistence** - SQLite with Prisma ORM
✅ **REST API** - Complete CRUD operations
✅ **Real-time Updates** - Frontend polls for progress

### UX Features
✅ **Responsive Design** - Works on mobile/tablet/desktop
✅ **Dark/Light Mode** - System preference detection
✅ **Progress Tracking** - Visual feedback during scans
✅ **Data Visualization** - Charts and graphs
✅ **Export Options** - JSON and CSV formats
✅ **Pause/Resume** - Control long-running scans

### Security Features
✅ **20+ Providers** - GitHub, AWS, Azure, Heroku, etc.
✅ **Severity Scoring** - Critical/High/Medium/Low
✅ **Confidence Metrics** - 0-100% match accuracy
✅ **Evidence Collection** - DNS + HTTP proof
✅ **Remediation Steps** - Fix instructions included

---

## 🐛 Troubleshooting Demo Issues

### If Backend Won't Start
```bash
cd backend
rm -rf node_modules package-lock.json
npm install
npx prisma generate
npm run dev
```

### If Frontend Won't Start
```bash
cd frontend
rm -rf node_modules package-lock.json
npm install
npm run dev
```

### If Database is Empty
```bash
cd backend
node prisma/seed.js
```

### If Scan Gets Stuck
```bash
# Check backend logs in terminal
# Look for errors or timeouts
# Restart backend if needed
```

### If Frontend Shows "API Error"
```bash
# Verify backend is running on port 3000
curl http://localhost:3000/health

# Check CORS settings in backend/.env
# Should be: CORS_ORIGIN=http://localhost:5173
```

---

## 📝 Presentation Talking Points

### Problem Statement
> "Subdomain takeover is a critical vulnerability where attackers can
> hijack subdomains pointing to unclaimed cloud resources. This can
> lead to phishing, malware distribution, and brand damage."

### Solution
> "SubVeil automates the detection process by continuously monitoring
> your domains, identifying dangling DNS records, and matching them
> against known vulnerable patterns across 20+ cloud providers."

### Architecture
> "The system uses a React frontend for visualization, Node.js backend
> for scanning logic, and SQLite for data persistence. The scanning
> engine uses DNS resolution, HTTP fingerprinting, and certificate
> transparency to discover and verify vulnerabilities."

### Value Proposition
> "Security teams can now automate subdomain takeover detection instead
> of manual checking. The system provides actionable findings with
> evidence and remediation steps, integrates via REST API, and scales
> to scan hundreds of domains."

---

## 🎯 Quick Demo Checklist

Before presenting:
- [ ] Backend running on port 3000
- [ ] Frontend running on port 5173
- [ ] Database seeded with 20 providers
- [ ] Browser open to http://localhost:5173
- [ ] Terminal ready for API demo
- [ ] Test domain ready (github.com recommended)
- [ ] Dark mode enabled (looks professional)
- [ ] Clear browser cache if needed
- [ ] Close unnecessary tabs/apps
- [ ] Screen resolution optimized for recording

During demo:
- [ ] Show dashboard overview
- [ ] Create a new scan
- [ ] Explain enumeration process
- [ ] Wait for/show findings
- [ ] Demonstrate export
- [ ] Show provider management
- [ ] Test pause/resume
- [ ] Demo API with curl
- [ ] Query database with SQL
- [ ] Toggle dark/light mode

After demo:
- [ ] Answer questions
- [ ] Show source code if asked
- [ ] Discuss extensibility
- [ ] Explain deployment options

---

## 🚀 Ready to Present!

Your SubVeil system is **100% functional** and ready to demonstrate. Follow this guide to showcase all features effectively. Good luck! 🎉
