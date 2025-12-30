import os
from flask import request, jsonify
from flask import Blueprint

try:
    import pyshark
except ImportError:
    pyshark = None

network_analysis_api = Blueprint('network_analysis_api', __name__)

@network_analysis_api.route('/api/upload-pcap', methods=['POST'])
def upload_pcap():
    """
    Accepts a PCAP file upload, parses it, and returns protocol/port/IP stats.
    """
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file part in request'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file'}), 400
    if not pyshark:
        return jsonify({'success': False, 'error': 'pyshark is not installed on the server'}), 500

    # Save file temporarily
    temp_path = f"/tmp/{file.filename}"
    file.save(temp_path)

    try:
        cap = pyshark.FileCapture(temp_path, only_summaries=True)
        protocol_counts = {}
        port_counts = {}
        ip_counts = {}
        total_packets = 0
        for pkt in cap:
            total_packets += 1
            proto = pkt.protocol if hasattr(pkt, 'protocol') else 'UNKNOWN'
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
            # Try to extract src/dst IP and port if available
            if hasattr(pkt, 'info'):
                info = pkt.info
                # Example info: "192.168.1.2 → 192.168.1.1 TCP 443 → 51514"
                import re
                ip_matches = re.findall(r'(\d+\.\d+\.\d+\.\d+)', info)
                for ip in ip_matches:
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
                port_matches = re.findall(r'\b(\d{2,5})\b', info)
                for port in port_matches:
                    port_counts[port] = port_counts.get(port, 0) + 1
        cap.close()
        os.remove(temp_path)
        return jsonify({
            'success': True,
            'total_packets': total_packets,
            'protocol_counts': protocol_counts,
            'port_counts': port_counts,
            'ip_counts': ip_counts
        })
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return jsonify({'success': False, 'error': f'Failed to parse file: {str(e)}'}), 500
