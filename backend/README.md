# SubVeil Backend

Subdomain Takeover Detection Engine - Backend API

## 🚀 Features

- **Subdomain Enumeration**: Discovers subdomains using:
  - Common subdomain brute-forcing
  - Certificate Transparency logs (crt.sh)
  - Permutation generation
  
- **DNS Analysis**: 
  - CNAME, A, and AAAA record resolution
  - Dangling DNS detection
  - Batch DNS lookups with concurrency control

- **HTTP Fingerprinting**:
  - Fetches HTTP responses from subdomains
  - Matches against 20+ provider fingerprints
  - Calculates confidence scores and severity levels

- **Vulnerability Detection**:
  - Detects subdomain takeover vulnerabilities
  - Supports 20+ cloud providers (GitHub Pages, AWS S3, Heroku, Azure, Vercel, etc.)
  - Evidence collection (DNS + HTTP)
  - Remediation recommendations

- **Scan Management**:
  - Create, start, pause, resume, delete scans
  - Real-time progress tracking
  - Concurrent scan support
  - Database persistence

- **RESTful API**:
  - Statistics and dashboard data
  - Scan CRUD operations
  - Finding management and export
  - Provider configuration

## 📋 Prerequisites

- Node.js >= 18.0.0
- npm or yarn

## 🛠️ Installation

1. **Navigate to backend directory**:
   ```bash
   cd backend
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Set up environment variables**:
   ```bash
   cp .env.example .env
   ```

4. **Generate Prisma Client**:
   ```bash
   npm run prisma:generate
   ```

5. **Initialize database**:
   ```bash
   npm run db:push
   ```

6. **Seed default providers**:
   ```bash
   npm run db:seed
   ```

## 🚀 Running the Server

### Development mode (with auto-reload):
```bash
npm run dev
```

### Production mode:
```bash
npm start
```

The server will start on `http://localhost:3000`

## 📡 API Endpoints

### Health Check
```
GET /health
```

### Statistics
```
GET /api/stats
```
Returns dashboard statistics including total subdomains, vulnerabilities, risk score, etc.

### Scans
```
GET    /api/scans              # Get all scans
POST   /api/scans              # Create and start a new scan
GET    /api/scans/:id          # Get scan details
POST   /api/scans/:id/pause    # Pause a running scan
POST   /api/scans/:id/resume   # Resume a paused scan
DELETE /api/scans/:id          # Delete a scan
```

### Findings
```
GET  /api/findings                # Get all findings
GET  /api/findings/export         # Export findings (JSON/CSV)
GET  /api/findings/:id            # Get finding details
POST /api/findings/:id/resolve    # Mark finding as resolved
```

### Providers
```
GET    /api/providers       # Get all providers
POST   /api/providers       # Create a new provider
GET    /api/providers/:id   # Get provider details
PUT    /api/providers/:id   # Update provider
DELETE /api/providers/:id   # Delete provider
```

## 🔍 How It Works

### 1. Subdomain Enumeration
When a scan is created for a domain (e.g., `example.com`):

1. **Brute Force**: Tests common subdomain names (www, api, dev, staging, etc.)
2. **Certificate Transparency**: Queries crt.sh for certificates issued for subdomains
3. **Permutations**: Generates variations with keywords

### 2. DNS Analysis
For each discovered subdomain:

1. Resolves CNAME records
2. Resolves A and AAAA records (IPv4 and IPv6)
3. Identifies "dangling" CNAMEs (CNAME exists but no A/AAAA records)

### 3. Vulnerability Detection
For dangling CNAMEs:

1. Checks if CNAME matches a known vulnerable provider pattern
2. Fetches HTTP response from the subdomain
3. Matches HTTP response against provider fingerprints
4. Calculates confidence score and severity level
5. Creates finding with evidence and remediation steps

### 4. Results Storage
All findings are stored in SQLite database with:
- Full DNS evidence
- HTTP response data
- Matched fingerprints
- Severity and confidence scores
- Remediation recommendations

## 🗄️ Database Schema

The backend uses Prisma ORM with SQLite:

- **Scan**: Scan metadata and status
- **Subdomain**: Discovered subdomains with DNS data
- **Finding**: Detected vulnerabilities
- **Provider**: Fingerprint database
- **Report**: Generated reports
- **Statistics**: Historical stats

## 🧪 Testing a Scan

### Example: Create a scan
```bash
curl -X POST http://localhost:3000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

### Example: Get scan status
```bash
curl http://localhost:3000/api/scans/{scan-id}
```

### Example: Get all findings
```bash
curl http://localhost:3000/api/findings
```

## 📊 Supported Providers

The backend includes fingerprints for 20+ providers:

1. GitHub Pages
2. AWS S3
3. Heroku
4. Azure Web Apps
5. Vercel
6. Netlify
7. Shopify
8. Fastly
9. AWS CloudFront
10. Bitbucket
11. Ghost
12. Pantheon
13. Tumblr
14. WordPress.com
15. Zendesk
16. Squarespace
17. Statuspage
18. Surge.sh
19. Unbounce
20. HelpJuice

## 🔧 Configuration

Edit `.env` file:

```env
PORT=3000
NODE_ENV=development
DATABASE_URL="file:./dev.db"
CORS_ORIGIN=http://localhost:5173
MAX_CONCURRENT_SCANS=5
DNS_TIMEOUT_MS=5000
HTTP_TIMEOUT_MS=10000
```

## 📁 Project Structure

```
backend/
├── prisma/
│   ├── schema.prisma       # Database schema
│   └── seed.js             # Database seeding
├── src/
│   ├── config/
│   │   └── providers.js    # Default provider fingerprints
│   ├── controllers/
│   │   ├── scanController.js
│   │   ├── findingController.js
│   │   ├── providerController.js
│   │   └── statsController.js
│   ├── routes/
│   │   ├── scanRoutes.js
│   │   ├── findingRoutes.js
│   │   ├── providerRoutes.js
│   │   └── statsRoutes.js
│   ├── services/
│   │   ├── dnsService.js           # DNS resolution
│   │   ├── subdomainService.js     # Subdomain enumeration
│   │   ├── httpFingerprintService.js  # HTTP fingerprinting
│   │   └── scanService.js          # Scan orchestration
│   └── server.js           # Express app
├── .env
├── .env.example
├── package.json
└── README.md
```

## 🚨 Important Notes

1. **Rate Limiting**: Be respectful when scanning. The tool includes built-in concurrency limits.

2. **Certificate Transparency**: CT log queries may be rate-limited by crt.sh.

3. **Legal**: Only scan domains you own or have permission to test.

4. **Database**: Uses SQLite by default. For production, consider PostgreSQL or MySQL.

5. **Timeouts**: DNS and HTTP timeouts are configurable via environment variables.

## 🐛 Troubleshooting

### Database issues:
```bash
# Reset database
rm prisma/dev.db
npm run db:push
npm run db:seed
```

### Dependencies:
```bash
# Clear and reinstall
rm -rf node_modules package-lock.json
npm install
```

### Prisma Client:
```bash
# Regenerate Prisma Client
npm run prisma:generate
```

## 📝 License

MIT

## 🤝 Contributing

Contributions welcome! Feel free to submit issues and pull requests.
