import requests
import json

class VirusTotalPlugin:
    def __init__(self):
        self.api_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        self.api_key = '3e9ee7b03c572c014a15494b8f8d6df00dd7462c35a06e6c859a682ef5373402'
    
    def run(self, url):
        content = self._get_content(url)
        scan_results = self._scan(content)
        return scan_results
    
    def _get_content(self, url):
        content = {}
        response = requests.get(url)
        content['js'] = response.content.decode('utf-8')
        response = requests.get(url, headers={'Accept': 'text/html'})
        content['html'] = response.content.decode('utf-8')
        response = requests.get(url, headers={'Accept': 'text/css'})
        content['css'] = response.content.decode('utf-8')
        response = requests.get(url, headers={'Accept': 'text/plain'})
        content['txt'] = response.content.decode('utf-8')
        return content
    
    def _scan(self, content):
        results = {}
        for type_, data in content.items():
            params = {'apikey': self.api_key}
            files = {'file': (type_, data)}
            response = requests.post(self.api_url, files=files, params=params)
            json_response = json.loads(response.content)
            results[type_] = {'scan_id': json_response['scan_id'], 'permalink': json_response['permalink']}
        return results

