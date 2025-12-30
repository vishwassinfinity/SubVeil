"""
Flask API Server for URL Information Extractor
Provides REST API endpoints to extract URL information
"""


from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from url_extractor import URLExtractor
from deep_scanner import DeepScanner
import os
from network_analysis_api import network_analysis_api


app = Flask(__name__, 
            static_folder='../frontend',
            template_folder='../frontend')
CORS(app)
app.register_blueprint(network_analysis_api)


@app.route('/')
def index():
    """Serve the main HTML page"""
    return render_template('index.html')


@app.route('/api/extract', methods=['POST'])
def extract_url_info():
    """
    API endpoint to extract URL information
    Expected JSON payload: {"url": "https://example.com"}
    """
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'success': False,
                'error': 'No URL provided in request'
            }), 400
        
        url = data['url'].strip()
        
        if not url:
            return jsonify({
                'success': False,
                'error': 'URL cannot be empty'
            }), 400
        
        # Extract URL information
        extractor = URLExtractor(url)
        info = extractor.extract_all_info()
        
        if info:
            return jsonify({
                'success': True,
                'url': url,
                'data': info
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Invalid URL format'
            }), 400
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Server error: {str(e)}'
        }), 500


@app.route('/api/extract-batch', methods=['POST'])
def extract_batch():
    """
    API endpoint to extract information from multiple URLs
    Expected JSON payload: {"urls": ["url1", "url2", ...]}
    """
    try:
        data = request.get_json()
        
        if not data or 'urls' not in data:
            return jsonify({
                'success': False,
                'error': 'No URLs provided in request'
            }), 400
        
        urls = data['urls']
        
        if not isinstance(urls, list):
            return jsonify({
                'success': False,
                'error': 'URLs must be provided as an array'
            }), 400
        
        results = []
        
        for url in urls:
            url = url.strip()
            if url:
                extractor = URLExtractor(url)
                info = extractor.extract_all_info()
                
                if info:
                    results.append({
                        'url': url,
                        'success': True,
                        'data': info
                    })
                else:
                    results.append({
                        'url': url,
                        'success': False,
                        'error': 'Invalid URL format'
                    })
        
        return jsonify({
            'success': True,
            'results': results
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Server error: {str(e)}'
        }), 500


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'URL Information Extractor API'
    })


@app.route('/api/deep-scan', methods=['POST'])
def deep_scan():
    """
    API endpoint to perform deep security scan of a URL
    Expected JSON payload: {"url": "https://example.com"}
    """
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'success': False,
                'error': 'No URL provided in request'
            }), 400
        
        url = data['url'].strip()
        
        if not url:
            return jsonify({
                'success': False,
                'error': 'URL cannot be empty'
            }), 400
        
        # Ensure URL has a scheme
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Perform deep scan
        scanner = DeepScanner(url)
        results = scanner.scan_all()
        
        return jsonify(results)
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Server error: {str(e)}'
        }), 500


if __name__ == '__main__':
    print("🚀 Starting URL Information Extractor API Server...")
    print("📡 Server running at: http://localhost:8000")
    print("🌐 Open your browser and navigate to: http://localhost:8000")
    print("-" * 50)
    app.run(debug=True, host='0.0.0.0', port=8000)
