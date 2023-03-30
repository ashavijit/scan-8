### Name 

### Scanning CSS JS Html Txt Files - scan8

### Description
This is a simple script to scan a directory for files with a specific extension and return the scanned files as json.


###  Reason

To scan a file ending with a specific extension such as HTML , CSS , JS , TXT  to scan for Malware or Trojan or any other malicious code using a simple script and VirusTotal API.

### Future Plans

I will be adding more features to this script in the future. Such as make a plugin for the #scan8 script to scan the files with a specific extension and return the results as json.

### Installation
    
 ```bash
git clone  <repo_url>
cd scan8
pip install -r requirements.txt
# For testing a url of your choice
# edit the url in the script in test.py
python test.py
```
### Response 

```json
{
    "js": {
        "scan_id": "ab2bc17c7e5d78d3c03a59bff82ec26637f1609da0ac1f4e2e402d34f803f91c-1678885719",
        "permalink": "https://www.virustotal.com/gui/file/ab2bc17c7e5d78d3c03a59bff82ec26637f1609da0ac1f4e2e402d34f803f91c/detection/f-ab2bc17c7e5d78d3c03a59bff82ec26637f1609da0ac1f4e2e402d34f803f91c-1678885719"
    },
    "html": {
        "scan_id": "75141f2df1ac35cd499ab5035fdf4edf70596507e3771ee55710b18c214b70bd-1678885721",
        "permalink": "https://www.virustotal.com/gui/file/75141f2df1ac35cd499ab5035fdf4edf70596507e3771ee55710b18c214b70bd/detection/f-75141f2df1ac35cd499ab5035fdf4edf70596507e3771ee55710b18c214b70bd-1678885721"
    },
    "css": {
        "scan_id": "0f0d5971291ccbf811cd28b739018cb82fd6ab61e55fb0ef1aad8bee9169f1bd-1678885723",
        "permalink": "https://www.virustotal.com/gui/file/0f0d5971291ccbf811cd28b739018cb82fd6ab61e55fb0ef1aad8bee9169f1bd/detection/f-0f0d5971291ccbf811cd28b739018cb82fd6ab61e55fb0ef1aad8bee9169f1bd-1678885723"
    },
    "txt": {
        "scan_id": "a2eb9ca193b66deb34ecc762916ac3c2273c72da95ee2f3d1a1822cb96ee67e5-1678885724",
        "permalink": "https://www.virustotal.com/gui/file/a2eb9ca193b66deb34ecc762916ac3c2273c72da95ee2f3d1a1822cb96ee67e5/detection/f-a2eb9ca193b66deb34ecc762916ac3c2273c72da95ee2f3d1a1822cb96ee67e5-1678885724"
    }
}
```





