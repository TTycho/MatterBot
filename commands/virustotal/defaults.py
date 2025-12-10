APIURL = {
    'virustotal': {
        # Base URL and keys are reused by the old-style module; do not change.
        'url': 'https://www.virustotal.com/api/v3/',
        'key': ['YOUR_VIRUSTOTAL_API_KEY_HERE'],
    },
    'malpedia': {
        # Optional Malpedia integration used for YARA rulesets.
        'enabled': False,
        'url': 'https://malpedia.caad.fkie.fraunhofer.de/api/get',
        'key': 'YOUR_MALPEDIA_API_KEY_HERE',
    },
}

CONTENTTYPE = 'application/json'

# MatterBot command bindings and visual settings
BINDS = ['virustotal', 'vt']
CHANS = []
COLOR = '#4285F4'  # VirusTotal / Google blue
