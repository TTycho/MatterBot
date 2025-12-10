"""Default settings for the AlienVault OTX module."""

BINDS = ['@alienvault', '@av']
CHANS = ['any']
COLOR = '#00CC66'  # LevelBlue / AlienVault green-ish

# Keep API URL and structure compatible with the old-style module.
APIURL = {
    'alienvault': {
        # Old module used: settings.APIURL['alienvault']['url']+endpoint
        'url': 'https://otx.alienvault.com/api/v1/indicators/',
        'key': 'CHANGEME',
        'contenttype': 'application/json',
    }
}
