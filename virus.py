from virustotal_plugin import VirusTotalPlugin 
import json
print ("Enter the URL to scan for malware")
url = input()
vt = VirusTotalPlugin()
response = vt.run(url)
print(response)
#save the results to a file called results.json
with open('results.json', 'w') as f:
    json.dump(response, f)

# fetching the results's permalink from the file results.json
with open('results.json', 'r') as f:
    data = json.load(f)
    for key, value in data.items():
        # get the permalink of html file
        if key == 'html':
            html_permalink = value['permalink']
            print(html_permalink)
            




