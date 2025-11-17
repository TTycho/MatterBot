# Default settings for the help module
BINDS = ['!help', '@help']
CHANS = ['any']
HELP = {
    'DEFAULT': {
        'desc': 'Provides help information about the bot and its commands.',
        'args': '[command]'
    }
}
VERSION = 2
CONTENTTYPE = 'application/json'
EXPECT = {  'subcommands':{
                # first subcommand is the default
                'me': {
                    # Allowed types are: hostname, domain; IP; URL; hash; ASN; string; longstring;
                    # User lowercase.
                    'types': ['command'], 

                    'options': ['verbose', 'silent'],
                    'help': 'Ask help for a command.'
                },
                'list': {
                    'types': [],
                    'help': 'A list of all commands.'
                  
                }
            },
            
            'help': {
                'args': 'A command or leave empty for a list of all commands.',
                'desc': 'Query the cyberthreat.nl API for the given IoC.',
            },
        }

