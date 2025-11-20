# Subdomain Takeover Detection System - Frontend

A professional, industry-ready frontend application for detecting and analyzing subdomain takeover vulnerabilities.

## Features

### 📊 Dashboard
- Real-time statistics and metrics
- Severity distribution charts
- Provider-based vulnerability analysis
- Recent findings overview

### 🔍 Scan Management
- Add and manage domains for scanning
- Monitor active scans in real-time
- View scan history and results
- Schedule automated scans

### ⚠️ Vulnerability Findings
- Detailed vulnerability reports with evidence
- DNS and HTTP response analysis
- Provider fingerprint matching
- Confidence scoring
- Remediation recommendations
- Export capabilities (JSON)

### ⚙️ Provider Configuration
- Manage detection providers (GitHub Pages, AWS S3, Heroku, Azure, Vercel, etc.)
- Configure CNAME patterns
- Define HTTP fingerprints
- Track detection statistics

### 📄 Reports
- Generate comprehensive security reports
- Multiple report types (Full Scan, Summary, Compliance)
- Download in various formats (PDF, HTML)
- Historical report access

## Tech Stack

- **React 19** - Latest React with hooks
- **React Router** - Client-side routing
- **Vite** - Fast build tool and dev server
- **Tailwind CSS** - Utility-first CSS framework
- **Recharts** - Data visualization
- **Lucide React** - Beautiful icon library
- **Axios** - HTTP client for API calls

## Getting Started

### Prerequisites
- Node.js 18+ and npm

### Installation

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

### Development Server
The app will run on `http://localhost:5173`

## Project Structure

```
frontend/
├── src/
│   ├── components/          # Reusable UI components
│   │   ├── Layout.jsx       # Main layout with navigation
│   │   ├── Card.jsx         # Card component variants
│   │   ├── Badge.jsx        # Severity badges
│   │   ├── Button.jsx       # Button component
│   │   └── StatCard.jsx     # Statistics card
│   ├── pages/              # Main application pages
│   │   ├── Dashboard.jsx    # Overview dashboard
│   │   ├── Scans.jsx        # Scan management
│   │   ├── Findings.jsx     # Vulnerability findings
│   │   ├── Providers.jsx    # Provider configuration
│   │   └── Reports.jsx      # Report generation
│   ├── App.jsx             # Main app component with routing
│   ├── main.jsx            # Application entry point
│   └── index.css           # Global styles
├── public/                 # Static assets
├── index.html             # HTML template
└── package.json           # Dependencies and scripts
```

## Key Features Explained

### Security-First Design
- **Passive reconnaissance** - All enumeration uses safe, legal methods
- **Evidence-based detection** - DNS records, HTTP responses, provider patterns
- **Risk scoring** - Confidence levels and severity ratings
- **Actionable insights** - Clear remediation steps

### Professional UI/UX
- Clean, modern interface
- Responsive design for all devices
- Intuitive navigation
- Real-time updates
- Interactive data visualizations

### Enterprise Ready
- Scalable architecture
- Component-based design
- Easy to extend with new providers
- API-ready structure
- Export and reporting capabilities

## API Integration

The frontend is designed to integrate with a backend API. Configure the API endpoint in your environment:

```javascript
// Example API configuration
const API_BASE_URL = process.env.VITE_API_URL || 'http://localhost:3000/api';
```

### Expected API Endpoints

- `GET /api/stats` - Dashboard statistics
- `GET /api/scans` - List all scans
- `POST /api/scans` - Start new scan
- `GET /api/findings` - Get vulnerability findings
- `GET /api/providers` - List providers
- `POST /api/reports` - Generate report

## Customization

### Adding New Providers
Edit `src/pages/Providers.jsx` to add new service providers with their fingerprints.

### Styling
The app uses Tailwind CSS. Customize colors and theme in `tailwind.config.js`.

### Components
All components are modular and reusable. Extend or modify them in the `src/components` directory.

## Contributing

When adding new features:
1. Follow the existing component structure
2. Use Tailwind CSS for styling
3. Keep components modular and reusable
4. Add proper error handling
5. Update documentation

## License

This project is part of a cybersecurity research and education initiative.

## Security Note

This tool is designed for authorized security testing only. Always ensure you have permission before scanning any domain.
