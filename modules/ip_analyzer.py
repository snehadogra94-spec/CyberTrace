import requests

def analyze_ip(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()

        if data['status'] == 'success':
            return {
                'ip': ip,
                'country': data.get('country', 'Unknown'),
                'region': data.get('regionName', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'isp': data.get('isp', 'Unknown'),
                'org': data.get('org', 'Unknown'),
                'timezone': data.get('timezone', 'Unknown'),
                'lat': data.get('lat', 0),
                'lon': data.get('lon', 0),
                'status': 'success'
            }
        else:
            return {'status': 'error', 'message': 'Invalid IP address'}

    except Exception as e:
        return {'status': 'error', 'message': str(e)}