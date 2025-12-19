# 🔍 SubVeil - URL Information Extractor

**SubVeil** is a comprehensive URL information extraction tool that reveals all hidden details from any website URL. It provides both a command-line interface and a beautiful web interface to extract and display URL components, DNS information, and more.

## ✨ Features

- **Complete URL Parsing**: Extract protocol, domain, subdomain, TLD, port, path, filename, query parameters, and fragments
- **DNS Lookup**: Get the IP address of any domain
- **Security Check**: Identify if the URL uses secure HTTPS protocol
- **URL Validation**: Validate URL format before processing
- **Dual Interface**: Use via command line or beautiful web interface
- **REST API**: JSON API endpoints for integration with other applications
- **Batch Processing**: Process multiple URLs at once via API

## 📋 Requirements

- Python 3.7 or higher
- pip (Python package installer)

## 🚀 Quick Start

### 1. Installation

Clone or download the project, then navigate to the backend directory:

```bash
cd backend
```

Install required dependencies:

```bash
pip install -r requirements.txt
```

Or install manually:

```bash
pip install Flask flask-cors
```

### 2. Run the Application

#### Option A: Web Interface (Recommended)

Start the Flask server:

```bash
python3 app.py
```

Open your browser and navigate to:
```
http://localhost:5000
```

#### Option B: Command Line

Run the standalone extractor:

```bash
python3 url_extractor.py
```

Enter a URL when prompted.

## 💻 Usage Examples

### Example URL:
```
https://www.example.com:8080/path/page.html?name=abc&id=10#section1
```

### Expected Output:
```
Protocol        : https
Domain Name     : example.com
Subdomain       : www
TLD             : .com
Port            : 8080
Path            : /path/page.html
File Name       : page.html
Query Params    : name=abc, id=10
Fragment        : section1
IP Address      : 93.184.216.34
Secure          : Yes
```

## 🔌 API Endpoints

### Extract Single URL
**POST** `/api/extract`

Request body:
```json
{
  "url": "https://www.example.com"
}
```

Response:
```json
{
  "success": true,
  "url": "https://www.example.com",
  "data": {
    "protocol": "https",
    "domain_name": "example.com",
    "subdomain": "www",
    "tld": ".com",
    "port": 443,
    "path": "/",
    "file_name": "None",
    "query_params": "None",
    "fragment": "None",
    "ip_address": "93.184.216.34",
    "secure": "Yes"
  }
}
```

### Extract Multiple URLs
**POST** `/api/extract-batch`

Request body:
```json
{
  "urls": [
    "https://www.example.com",
    "https://github.com/username"
  ]
}
```

### Health Check
**GET** `/health`

## 📁 Project Structure

```
SubVeil/
├── backend/
│   ├── app.py                 # Flask API server
│   ├── url_extractor.py       # Core URL extraction logic
│   └── requirements.txt       # Python dependencies
├── frontend/
│   └── index.html            # Web interface
└── README.md                 # This file
```

## 🛠️ Technology Stack

- **Backend**: Python, Flask
- **Frontend**: HTML, CSS, JavaScript
- **Libraries**: 
  - urllib.parse (URL parsing)
  - socket (DNS lookup)
  - re (URL validation)
  - Flask (Web server)
  - flask-cors (CORS support)

## 🎯 Use Cases

- **Web Development**: Analyze and debug URLs during development
- **SEO Analysis**: Extract URL components for SEO optimization
- **Security Auditing**: Check URL security and structure
- **Education**: Learn about URL structure and components
- **Data Extraction**: Programmatically extract URL information for data processing

## 🔒 Error Handling

The application gracefully handles:
- Invalid URL formats
- DNS lookup failures
- Network errors
- Empty inputs

## 📝 Notes

- Default ports are automatically assigned (HTTP: 80, HTTPS: 443, FTP: 21)
- DNS lookup requires internet connectivity
- Some URLs may not resolve if DNS is unavailable or domain doesn't exist

## 🤝 Contributing

Feel free to fork, modify, and use this project for your needs!

## 📄 License

This project is open source and available for educational and commercial use.

## 👨‍💻 Author

Built with ❤️ for the developer community

---

**Happy URL Extracting! 🔍**
