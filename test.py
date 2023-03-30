from virustotal_plugin import VirusTotalPlugin
url='https://www.github.com'
vt = VirusTotalPlugin()
response = vt.run(url)
print(response)
