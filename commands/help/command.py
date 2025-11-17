import logging
from pathlib import Path
# try:
#     from commands.help import defaults as settings
# except ModuleNotFoundError: # local test run
#     import defaults as settings
#     if Path('settings.py').is_file():
#         import settings
# else:
#     if Path('commands/help/settings.py').is_file():
#         try:
#             from commands.hybridanalysis import settings
#         except ModuleNotFoundError: # local test run
#             import settings

log = logging.getLogger('HelpCommand')

def process(task, channame, username, files, mmDriver):
    """
    Process help commands and return help messages.

    Args:
        command (str): The command that was triggered.
        channame (str): The name of the channel where the command was triggered.
        username (str): The username of the user who triggered the command.
        params (list): List of parameters passed with the command.
        files (list): List of files attached to the message.
        mmDriver: Mattermost driver instance.

    Returns:
        dict: A dictionary containing the help messages to be sent.
    """
    messages = []

    # if not params:
    #     # Get general help information
    #     commands = set()
    #     for module in self.commands:
    #         if self.isallowed_module(userid, module, chaninfo):
    #             for bind in self.commands[module]['binds']:
    #                 commands.add('`' + bind + '`')
    #     text = "I know about: `"+'`, `'.join(sorted(options.Matterbot['helpcmds']))+"`, " + ', '.join(sorted(commands)) + " here.\n"
    #     text += "*Remember that not every command works everywhere: this depends on the configuration. Modules may offer additional help if you add the subcommand.*"
    #     messages.append({'text': text})
    # else:
    #     # Get specific help information for modules
    #     for module in self.commands:
    #         if self.isallowed_module(userid, module, chaninfo):
    #             if set(params) & set(self.commands[module]['binds']):
    #                 try:
    #                     text = ''
    #                     HELP = self.commands[module]['settings']['help']
    #                     paramsubcommands = set(params) & set(HELP)
    #                     if len(paramsubcommands) == 0:
    #                         if 'DEFAULT' in HELP:
    #                             # Trigger the default help message
    #                             args = HELP['DEFAULT']['args'] if HELP['DEFAULT']['args'] else None
    #                             desc = HELP['DEFAULT']['desc']
    #                             text += '**Module**: `' + module + '`'
    #                             text += '\n**Description**: '
    #                             text += desc
    #                             if args:
    #                                 text += '\n**Arguments**: `' + args + '`'
    #                             subcommands = set()
    #                             if len(HELP)>1:
    #                                 text += '\n**Subcommands**: '
    #                             for subcommand in HELP:
    #                                 if subcommand != 'DEFAULT':
    #                                     subcommands.add(subcommand)
    #                             if len(subcommands)>0:
    #                                 text += '`' + '`, `'.join(subcommands) + '`'
    #                     else: # paramsubcommands >= 1
    #                         for subcommand in paramsubcommands:
    #                             args = HELP[subcommand]['args'] if HELP[subcommand]['args'] else None
    #                             desc = HELP[subcommand]['desc']
    #                             text += '**Module**: `' + module + '`/`' + subcommand + '`'
    #                             text += '\n**Description**: '
    #                             text += desc
    #                             if args:
    #                                 text += '\n**Arguments**: `' + args + '`'
    #                     if len(text)>0:
    #                         messages.append({'text': text})
    #                 except NameError:
    #                     messages.append({'text': text})
    messages = ["work in progress"]
    return {'messages': messages}

# here for documentation
def help_message(self, userid, params, chaninfo, rootid):
    chanid=chaninfo['id']
    commands = set()
    if not params:
        for module in self.commands:
            if self.isallowed_module(userid, module, chaninfo):
                for bind in self.commands[module]['binds']:
                    commands.add('`' + bind + '`')
        text =  "I know about: `"+'`, `'.join(sorted(options.Matterbot['helpcmds']))+"`, " + ', '.join(sorted(commands)) + " here.\n"
        text += "*Remember that not every command works everywhere: this depends on the configuration. Modules may offer additional help if you add the subcommand.*"
        self.send_message(chanid, text, rootid)        
    else:
        # User is asking for specific module help
        for module in self.commands:
            if self.isallowed_module(userid, module, chaninfo):
                if set(params) & set(self.commands[module]['binds']): # for future use
                    try:
                        text = ''
                        HELP = self.commands[module]['help']
                        paramsubcommands = set(params) & set(HELP)
                        if len(paramsubcommands) == 0:
                            if 'DEFAULT' in HELP:
                                # Trigger the default help message
                                args = HELP['DEFAULT']['args'] if HELP['DEFAULT']['args'] else None
                                desc = HELP['DEFAULT']['desc']
                                text += '**Module**: `' + module + '`'
                                text += '\n**Description**: '
                                text += desc
                                if args:
                                    text += '\n**Arguments**: `' + args + '`'
                                subcommands = set()
                                if len(HELP)>1:
                                    text += '\n**Subcommmands**: '
                                for subcommand in HELP:
                                    if subcommand != 'DEFAULT':
                                        subcommands.add(subcommand)
                                if len(subcommands)>0:
                                    text += '`' + '`, `'.join(subcommands) + '`'
                        else: # paramsubcommands >= 1
                            for subcommand in paramsubcommands:
                                args = HELP[subcommand]['args'] if HELP[subcommand]['args'] else None
                                desc = HELP[subcommand]['desc']
                                text += '**Module**: `' + module + '`/`' + subcommand + '`'
                                text += '\n**Description**: '
                                text += desc
                                if args:
                                    text += '\n**Arguments**: `' + args + '`'
                        if len(text)>0:
                                self.send_message(chanid, text, rootid)
                    except NameError:
                        self.send_message(chanid, text, rootid)

