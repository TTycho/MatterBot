import logging
from typing import List, Literal, TypedDict
from core.typevalidators import Domain, IPv4, LongString, String

class commands():
    """
    The help module give help on al other modules.
    """
    def __init__(self):
        self.module_name = self.__class__.__module__.split('.')[-1]

    def help(self, parameters: List[String], options: str, modules=None, *args, **kwargs) -> dict:
        """Default. Will give help on any known command."""
        logging.warning(f"Modules is: {kwargs.get('modules')} or {modules}")
        
        data = {
            "module": __package__, 
            "source": "Matterbot Help Module", 
            "responses": []
            }

        if not parameters:
            logging.warning("No parameters provided in the command.")

            for module_name, mod in modules.items():
                doc = mod.get('doc', 'Module has no documentation')
                data['responses'].append({"category":"Command", "subcategory":"", 'datapoint': module_name, 'value': doc})



            pass
        else:
            logging.info(f"Help requested with parameters: {parameters}")
            pass

        return data

    def extra(self, parameters: List[None], options: str, modules={}):
        """Help without parameters gives you a list of all commands."""
        
        data = {
            "module": __package__, 
            "source": "Matterbot Help Module", 
            "responses": []
            }

        for module_name, mod in modules.items():
            doc = mod.get('doc', 'Module has no documentation')
            data['responses'].append({'datapoint': module_name, 'value': doc})

        logging.info("Prepared help data with %d entries", len(data['data']))
        pass
        pass

    def abc(self, parameters: List[Domain|IPv4], options: str, channel: str, username: str, files: list, conn):
        pass


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

