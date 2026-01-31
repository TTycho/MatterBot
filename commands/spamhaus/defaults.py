APIURL = {
    'spamhaus': {
        # Credentials / keys (override in settings.py)
        'username': 'YOUR_SIA_USERNAME',
        'password': 'YOUR_SIA_PASSWORD',
        # Default dataset for IP lookups (XBL, CSS, BCL, ALL)
        'dataset_default': 'ALL',
    }
}

CONTENTTYPE = 'application/json'

BINDS = ['@spamhaus', '@sh']
CHANS = []
COLOR = '#ff6600'
