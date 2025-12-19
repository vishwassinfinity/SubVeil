"""
URL Information Extractor
Extracts and displays all possible information from a website URL
Includes WHOIS and Domain Intelligence features
"""

from urllib.parse import urlparse, parse_qs
import socket
import re
import whois
from datetime import datetime, timezone


class URLExtractor:
    """Class to extract comprehensive information from URLs"""
    
    def __init__(self, url):
        self.url = url
        self.parsed = None
        self.info = {}
        
    def validate_url(self):
        """Validate URL format"""
        # Basic URL pattern matching
        url_pattern = re.compile(
            r'^(https?|ftp)://'  # protocol
            r'([a-zA-Z0-9.-]+)'   # domain
            r'(:[0-9]+)?'         # optional port
            r'(/.*)?$'            # path
        )
        return bool(url_pattern.match(self.url))
    
    def extract_all_info(self):
        """Extract all information from the URL"""
        if not self.validate_url():
            return None
        
        try:
            self.parsed = urlparse(self.url)
            
            # Extract basic components
            self.info['protocol'] = self.parsed.scheme
            self.info['domain_name'] = self.parsed.hostname or ''
            self.info['port'] = self.parsed.port or self._get_default_port()
            self.info['path'] = self.parsed.path or '/'
            self.info['query_params'] = self._extract_query_params()
            self.info['fragment'] = self.parsed.fragment or 'None'
            self.info['secure'] = 'Yes' if self.parsed.scheme == 'https' else 'No'
            
            # Extract subdomain and TLD
            subdomain, tld = self._extract_subdomain_tld()
            self.info['subdomain'] = subdomain
            self.info['tld'] = tld
            
            # Extract filename from path
            self.info['file_name'] = self._extract_filename()
            
            # Get IP address via DNS lookup
            self.info['ip_address'] = self._get_ip_address()
            
            # Get WHOIS and Domain Intelligence
            whois_data = self._get_whois_intelligence()
            self.info['whois'] = whois_data
            
            return self.info
            
        except Exception as e:
            return None
    
    def _get_default_port(self):
        """Get default port based on protocol"""
        defaults = {
            'http': 80,
            'https': 443,
            'ftp': 21
        }
        return defaults.get(self.parsed.scheme, 'N/A')
    
    def _extract_query_params(self):
        """Extract query parameters as key-value pairs"""
        if not self.parsed.query:
            return 'None'
        
        params = parse_qs(self.parsed.query)
        # Flatten the values (parse_qs returns lists)
        param_list = [f"{k}={v[0]}" for k, v in params.items()]
        return ', '.join(param_list)
    
    def _extract_subdomain_tld(self):
        """Extract subdomain and top-level domain"""
        hostname = self.parsed.hostname or ''
        
        if not hostname:
            return 'None', 'None'
        
        parts = hostname.split('.')
        
        # If only one part, no subdomain or TLD
        if len(parts) == 1:
            return 'None', 'None'
        
        # Extract TLD (last part)
        tld = '.' + parts[-1]
        
        # Extract subdomain (everything except last two parts for standard domains)
        if len(parts) > 2:
            subdomain = '.'.join(parts[:-2])
        else:
            subdomain = 'None'
        
        return subdomain, tld
    
    def _extract_filename(self):
        """Extract filename from the path"""
        path = self.parsed.path
        
        if not path or path == '/':
            return 'None'
        
        # Get the last part of the path
        filename = path.split('/')[-1]
        
        # Check if it has a file extension
        if '.' in filename:
            return filename
        
        return 'None'
    
    def _get_ip_address(self):
        """Get IP address of the domain using DNS lookup"""
        try:
            hostname = self.parsed.hostname
            if hostname:
                ip = socket.gethostbyname(hostname)
                return ip
            return 'Unable to resolve'
        except socket.gaierror:
            return 'Unable to resolve'
        except Exception:
            return 'Error during lookup'
    
    def _get_whois_intelligence(self):
        """Get WHOIS information and perform domain intelligence analysis"""
        try:
            hostname = self.parsed.hostname
            if not hostname:
                return self._empty_whois_data()
            
            # Perform WHOIS lookup
            domain_info = whois.whois(hostname)
            
            # Extract data safely
            registrar = self._safe_extract(domain_info.registrar)
            organization = self._safe_extract(domain_info.org)
            creation_date = self._safe_extract_date(domain_info.creation_date)
            expiry_date = self._safe_extract_date(domain_info.expiration_date)
            updated_date = self._safe_extract_date(domain_info.updated_date)
            
            # Calculate domain age
            domain_age_info = self._calculate_domain_age(creation_date)
            
            # Calculate trust score
            trust_score, risk_level = self._calculate_trust_score(
                domain_age_info['age_days'],
                registrar,
                organization,
                expiry_date
            )
            
            return {
                'available': True,
                'registrar': registrar,
                'organization': organization,
                'creation_date': creation_date,
                'expiry_date': expiry_date,
                'updated_date': updated_date,
                'domain_age': domain_age_info['age_text'],
                'age_days': domain_age_info['age_days'],
                'trust_score': trust_score,
                'risk_level': risk_level,
                'name_servers': self._safe_extract_list(domain_info.name_servers)
            }
            
        except Exception as e:
            return self._empty_whois_data()
    
    def _safe_extract(self, value):
        """Safely extract string value from WHOIS data"""
        if value is None:
            return 'Not Available'
        if isinstance(value, list) and len(value) > 0:
            return str(value[0])
        return str(value) if value else 'Not Available'
    
    def _safe_extract_date(self, value):
        """Safely extract and format date from WHOIS data"""
        if value is None:
            return 'Not Available'
        
        try:
            if isinstance(value, list) and len(value) > 0:
                date_obj = value[0]
            else:
                date_obj = value
            
            if isinstance(date_obj, datetime):
                return date_obj.strftime('%Y-%m-%d')
            return str(date_obj)
        except:
            return 'Not Available'
    
    def _safe_extract_list(self, value):
        """Safely extract list values"""
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item) for item in value[:3]]  # Limit to 3 name servers
        return [str(value)]
    
    def _calculate_domain_age(self, creation_date):
        """Calculate domain age from creation date"""
        if creation_date == 'Not Available':
            return {
                'age_text': 'Unknown',
                'age_days': 0
            }
        
        try:
            # Parse the date string
            date_obj = datetime.strptime(creation_date, '%Y-%m-%d')
            
            # Calculate age
            now = datetime.now()
            age_delta = now - date_obj
            age_days = age_delta.days
            
            # Format age text
            years = age_days // 365
            months = (age_days % 365) // 30
            
            if years > 0:
                age_text = f"{years} year{'s' if years > 1 else ''}"
                if months > 0:
                    age_text += f" {months} month{'s' if months > 1 else ''}"
            elif months > 0:
                age_text = f"{months} month{'s' if months > 1 else ''}"
            else:
                age_text = f"{age_days} day{'s' if age_days > 1 else ''}"
            
            return {
                'age_text': age_text,
                'age_days': age_days
            }
        except:
            return {
                'age_text': 'Unknown',
                'age_days': 0
            }
    
    def _calculate_trust_score(self, age_days, registrar, organization, expiry_date):
        """Calculate domain trust score and risk level"""
        score = 0
        
        # Age-based scoring (max 40 points)
        if age_days > 1825:  # > 5 years
            score += 40
        elif age_days > 730:  # > 2 years
            score += 30
        elif age_days > 365:  # > 1 year
            score += 20
        elif age_days > 180:  # > 6 months
            score += 10
        else:  # < 6 months
            score += 0
        
        # Registrar scoring (max 25 points)
        reputable_registrars = [
            'godaddy', 'namecheap', 'google', 'markmonitor', 
            'networksolutions', 'enom', 'tucows', 'gandi'
        ]
        
        if registrar != 'Not Available':
            registrar_lower = registrar.lower()
            if any(rep in registrar_lower for rep in reputable_registrars):
                score += 25
            else:
                score += 15
        
        # Organization scoring (max 20 points)
        if organization != 'Not Available' and organization != 'Privacy Protected':
            score += 20
        elif organization == 'Privacy Protected':
            score += 10  # Privacy is okay, but less transparent
        
        # Expiry date scoring (max 15 points)
        if expiry_date != 'Not Available':
            try:
                expiry_obj = datetime.strptime(expiry_date, '%Y-%m-%d')
                days_until_expiry = (expiry_obj - datetime.now()).days
                
                if days_until_expiry > 365:  # More than a year
                    score += 15
                elif days_until_expiry > 90:  # More than 3 months
                    score += 10
                elif days_until_expiry > 0:
                    score += 5
            except:
                pass
        
        # Determine risk level
        if score >= 75:
            risk_level = 'Low'
        elif score >= 50:
            risk_level = 'Medium'
        elif score >= 25:
            risk_level = 'High'
        else:
            risk_level = 'Critical'
        
        return score, risk_level
    
    def _empty_whois_data(self):
        """Return empty WHOIS data structure"""
        return {
            'available': False,
            'registrar': 'Not Available',
            'organization': 'Not Available',
            'creation_date': 'Not Available',
            'expiry_date': 'Not Available',
            'updated_date': 'Not Available',
            'domain_age': 'Unknown',
            'age_days': 0,
            'trust_score': 0,
            'risk_level': 'Unknown',
            'name_servers': []
        }
    
    def print_info(self):
        """Print extracted information in a formatted manner"""
        if not self.info:
            print("❌ Invalid URL format. Please provide a valid URL.")
            return
        
        print("\n" + "="*50)
        print("🔍 URL INFORMATION EXTRACTOR")
        print("="*50)
        print(f"\n📌 Original URL: {self.url}\n")
        print("-"*50)
        
        labels = {
            'protocol': 'Protocol',
            'domain_name': 'Domain Name',
            'subdomain': 'Subdomain',
            'tld': 'TLD',
            'port': 'Port',
            'path': 'Path',
            'file_name': 'File Name',
            'query_params': 'Query Params',
            'fragment': 'Fragment',
            'ip_address': 'IP Address',
            'secure': 'Secure'
        }
        
        for key, label in labels.items():
            value = self.info.get(key, 'N/A')
            print(f"{label:<16}: {value}")
        
        print("="*50 + "\n")
    
    def get_info_dict(self):
        """Return information as a dictionary"""
        return self.info


def main():
    """Main function to run the URL extractor"""
    print("🔗 URL Information Extractor")
    print("="*50)
    
    # Get URL input from user
    url = input("\nEnter URL: ").strip()
    
    if not url:
        print("❌ No URL provided!")
        return
    
    # Create extractor and process
    extractor = URLExtractor(url)
    info = extractor.extract_all_info()
    
    if info:
        extractor.print_info()
    else:
        print("\n❌ Invalid URL format. Please provide a valid URL.")
        print("Example: https://www.example.com:8080/path/page.html?name=abc&id=10#section1")


if __name__ == "__main__":
    main()
