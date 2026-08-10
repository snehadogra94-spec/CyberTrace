import re
import requests

def analyze_email_header(raw_header):
    try:
        results = {
            'from': '',
            'to': '',
            'subject': '',
            'date': '',
            'received_ips': [],
            'spf': '',
            'dkim': '',
            'status': 'success'
        }

        from_match = re.search(r'^From:(.+)$', raw_header, re.MULTILINE | re.IGNORECASE)
        to_match = re.search(r'^To:(.+)$', raw_header, re.MULTILINE | re.IGNORECASE)
        subject_match = re.search(r'^Subject:(.+)$', raw_header, re.MULTILINE | re.IGNORECASE)
        date_match = re.search(r'^Date:(.+)$', raw_header, re.MULTILINE | re.IGNORECASE)

        results['from'] = from_match.group(1).strip() if from_match else 'Not found'
        results['to'] = to_match.group(1).strip() if to_match else 'Not found'
        results['subject'] = subject_match.group(1).strip() if subject_match else 'Not found'
        results['date'] = date_match.group(1).strip() if date_match else 'Not found'

        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        all_ips = re.findall(ip_pattern, raw_header)

        public_ips = []
        for ip in all_ips:
            parts = ip.split('.')
            if not (parts[0] == '10' or
                    (parts[0] == '172' and 16 <= int(parts[1]) <= 31) or
                    (parts[0] == '192' and parts[1] == '168') or
                    parts[0] == '127'):
                if ip not in public_ips:
                    public_ips.append(ip)

        for ip in public_ips[:3]:
            ip_info = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
            if ip_info.get('status') == 'success':
                results['received_ips'].append({
                    'ip': ip,
                    'country': ip_info.get('country', 'Unknown'),
                    'city': ip_info.get('city', 'Unknown'),
                    'isp': ip_info.get('isp', 'Unknown')
                })

        results['spf'] = 'Pass' if 'spf=pass' in raw_header.lower() else \
                         'Fail' if 'spf=fail' in raw_header.lower() else 'Not found'
        results['dkim'] = 'Pass' if 'dkim=pass' in raw_header.lower() else \
                          'Fail' if 'dkim=fail' in raw_header.lower() else 'Not found'

        results['spoof_alert'] = results['spf'] == 'Fail' or results['dkim'] == 'Fail'

        return results

    except Exception as e:
        return {'status': 'error', 'message': str(e)} 