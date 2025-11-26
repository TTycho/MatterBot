#!/usr/bin/env python3

import ast
import asyncio
import collections
import concurrent.futures
import copy
import fnmatch
import importlib.util
import inspect
import json
import logging
import os
import pathlib
import sys
import configargparse
import typing
from typing import get_type_hints, get_origin, get_args

from mattermostdriver import Driver
from core import helpers
from core import typevalidators
from core.formatters import format_as_tables


class TokenAuth():
    def __call__(self, r):
        r.headers['Authorization'] = "Bearer %s" % options.Matterbot['password']
        r.headers['X-Requested-With'] = 'XMLHttpRequest'
        return r

class MattermostManagers(object):
    def __init__(self):
        self.mmDriver = Driver(options={
            'url'       : options.Matterbot['host'],
            'port'      : options.Matterbot['port'],
            'login_id'  : options.Matterbot['username'],
            'token'     : options.Matterbot['password'],
            'basepath'  : options.Matterbot['basepath'],
            'scheme'    : options.Matterbot['scheme'],
            'auth'      : TokenAuth,
            #'debug'     : options.debug,
            'keepalive' : True,
            'keepalive_delay': 60,
            'websocket_kw_args': {'ping_interval': 30},
        })
        try:
            self.mmDriver.login()
        except:
            log.error("Mattermost server is unreachable. Perhaps it is down, or you might have misconfigured one or more setting(s). Shutting down!")
            return False
        self.me = self.mmDriver.users.get_user(user_id='me')
        log.info("Who am I: %s" % (self.me,))
        self.my_id = self.me['id']
        self.my_team_name = options.Matterbot['teamname']
        self.my_team_id = self.mmDriver.teams.get_team_by_name(self.my_team_name)['id']
        # Load an existing module channel binding map if present
        modulepath = options.Modules['commanddir'].strip('/')
        sys.path.append(modulepath)
        self.modules = {}
        self.modules = {}
        self.binds = {}
        self.channelmapping = { 'idtoname': {}, 'nametoid': {}}
        
        '''
        Bindmap should become: {'!help': ['help'], '@help': ['help'], '@bootloaders': ['bootloaders'], '@bl': ['bootloaders'], '@ioc': ['bootloaders', 'cyberthreat', 'misp', 'malpedia', 'loldrivers', 'malwarebazaar', 'ripewhois', 'lolbas', 'urlhaus', 'virustotal', 'threatfox', 'ipwhois', 'sslmate', 'gtfobins', 'bssc'], '@upi': ['unprotectit'], '@ttp': ['unprotectit'], '@cyberthreat': ['cyberthreat'], '@ct': ['cyberthreat'], '@misp': ['misp'], 'hello': ['example'], 'hi': ['example'], 'hiya': ['example'], 'howdi': ['example'], 'greetings': ['example'], '@hybridanalysis': ['hybridanalysis'], '@ha': ['hybridanalysis'], '@malpedia': ['malpedia'], '@mp': ['malpedia'], '@loldrivers': ['loldrivers'], '@ld': ['loldrivers'], '@analyze': ['analyze'], '@malwarebazaar': ['malwarebazaar'], '@mb': ['malwarebazaar'], '@alienvault': ['alienvault'], '@av': ['alienvault'], '@tlsgrab': ['tlsgrab'], '@tg': ['tlsgrab'], '@ripewhois': ['ripewhois'], '@docgen': ['docgen'], '@lolbas': ['lolbas'], '@lb': ['lolbas'], '@ewa': ['ewa'], '@urlhaus': ['urlhaus'], '@uh': ['urlhaus'], '@tweetfeed': ['tweetfeed'], '@virustotal': ['virustotal'], '@vt': ['virustotal'], '@greynoise': ['greynoise'], '@threatfox': ['threatfox'], '@tf': ['threatfox'], '@censys': ['censys'], '@snow': ['snowplough'], '@snowplough': ['snowplough'], '@sp': ['snowplough'], '@ipwhois': ['ipwhois'], '@sslmate': ['sslmate'], '@geo': ['geolookup'], '@geolookup': ['geolookup'], '@gl': ['geolookup'], '@ai': ['chatgpt'], '@openai': ['chatgpt'], '@chatgpt': ['chatgpt'], '@gpt': ['chatgpt'], '@robot': ['chatgpt'], '@qualys': ['qualys'], '@ql': ['qualys'], '@am': ['attackmatrix'], '@attackmatrix': ['attackmatrix'], '@leakix': ['leakix'], '@li': ['leakix'], '@wiki': ['wikijs'], '@wikijs': ['wikijs'], '@asnwhois': ['asnwhois'], '@asn': ['asnwhois'], '@gtfobins': ['gtfobins'], '@gb': ['gtfobins'], '@bssc': ['bssc'], '@dice': ['diceroll'], '@roll': ['diceroll'], '@shodan': ['shodan']}

        '''
        try:
            bindmap = pathlib.Path(options.Matterbot['bindmap'])
            if bindmap.is_file() and False: # temporaly disable loading existing bindmap
                with open(bindmap, 'r') as f:
                    self.modules = json.load(f) # Oops. commands was also used for commands class.
                    log.info(f"loaded bindmap and populated self.modules: {self.modules}")
                    log.info(f"")
                    log.info(f"Keys are {self.modules.keys()}")
                    for module in self.modules.keys():
                        log.debug(f"Working on module {module}")
                        for bind in self.modules[module]['BINDS']:
                            if bind not in self.binds:
                                self.binds[bind] = []
                            log.info(f"adding module '{module}' to bind '{bind}'")
                            self.binds[bind].append(module)
                log.debug(f"self.binds is now: {self.binds}")
                log.info(f"Loaded existing bindmap file {options.Matterbot['bindmap']} to {self.modules}")
        except: # There is no existing command map, or it failed loading; create an empty map instead.
            pass



        # Load any new modules by listing directories under _modulepath_
        for root, dirs, files in os.walk(modulepath):
            """Auto-discover command modules and register their public callables.

            For each directory containing a ``command.py`` file we import the
            module and collect all functions that do not
            start with ``_``. These are treated as subcommands and stored in
            ``self.modules[module_name]['commands']``.
            """
            if "command.py" in files:
                module_name = root.split('/')[-1].lower()
                module = importlib.import_module(module_name + '.' + 'command', package=module_name)

                self.modules[module_name] = {}
                log.warning(f"Module: {module_name}")

                # Use the module itself as the documentation source (module docstring)
                self.modules[module_name]['doc'] = inspect.getdoc(module)

                # Determine default command: first public callable in the module
                public_callables = [
                    name for name, obj in module.__dict__.items()
                    if inspect.isfunction(obj)
                    and not name.startswith('_')
                    and getattr(obj, "__module__", None) == getattr(module, "__name__", None)
                ]
                self.modules[module_name]['defaultcommand'] = public_callables[0] if public_callables else None

                # Build commands dict using the already computed public_callables
                self.modules[module_name]['commands'] = {}
                for name in public_callables:
                    func = getattr(module, name)

                    ann = getattr(func, "__annotations__", {})
                    # We only care about the 'parameters' annotation (List[...]) used for argument typing
                    annotations = ann.get("parameters")
                    annotationset = helpers.expand_annotation(annotations)
                    self.modules[module_name]['commands'][name] = {
                        "originalname": name,
                        "doc": inspect.getdoc(func),
                        "annotations": annotations,
                        "types": annotationset,
                        "function": func,
                    }

                log.debug(f"Allowed subcommands: {self.modules[module_name]['commands']}")
                log.warning(f"Loaded module: {module_name}; {self.modules[module_name]}")

                if module_name in self.modules: # What is this check for? Skip if already loaded via bindmap?
                    settings = {} # if 'settings' was set. This deletes it again.
                    # Is it not better to load command modules first and then populate self.modules with 
                    # information from the bindmap?
                    
                    try:
                        defaults = importlib.import_module(modulepath + '.' + module_name + '.' + 'defaults')
                        # settings.update(defaults.__dict__)
                        settings.update({k: v for k, v in defaults.__dict__.items() if not k.startswith('__')})
                    except ImportError:
                        log.error(f"{module_name}.default did not load.")
                    
                    try:
                        overridesettings = importlib.import_module(modulepath + '.' + module_name + '.' + 'settings')
                        settings.update(overridesettings.__dict__)
                        settings.update({k: v for k, v in overridesettings.__dict__.items() if not k.startswith('__')})
                    except ImportError:
                        log.info(f"{module_name}.settings did not load.")

                    # log.error(f"{settings}")
                    self.modules[module_name]['settings'] = settings
                    # log.debug(f"Self commands: {self.modules}")
                    for bind in settings['BINDS']:
                        if bind not in self.binds:
                            self.binds[bind] = []
                        self.binds[bind].append(module_name)
                    log.debug(f"Binds: {self.binds}")
                try:
                    with open(options.Matterbot['bindmap'],'w') as f:
                        log.warning(f"""
                                    Bindmap is: {self.binds}
                                    """)
                        json.dump(self.binds,f)
                except:
                    log.error("An error occurred writing the bindmap file: %s" % (options.Matterbot['bindmap'],))
        

        # Start the websocket
        self.mmDriver.init_websocket(self.handle_raw_message)


    async def update_bindmap(self): # XXX have to look into this. Probably changed.
        try:
            self.bindmap = copy.deepcopy(self.modules)
            for module in self.bindmap:
                del self.bindmap[module]['settings']
                del self.bindmap[module]['process']
            with open(options.Matterbot['bindmap'],'w') as f:
                json.dump(self.bindmap,f)
        except:
            raise
            log.error("An error occurred updating the `%s` bindmap file; config changes were not successfully saved!" % (options.Matterbot['bindmap'],))

    async def handle_raw_message(self, raw_json: str):
        try:
            data = json.loads(raw_json)
            asyncio.create_task(self.handle_message(data))
        except json.JSONDecodeError as e:
            return

    async def handle_message(self, message: dict):
        try:
            if 'event' in message:
                post_data = message['data']
                if 'post' in post_data:
                    await self.handle_post(post_data)
        except json.JSONDecodeError as e:
            log.error(e)

    async def send_message(self, chanid, text, postid=None):
        try:
            channame = self.chanid_to_chaninfo(chanid)['name']
            log.info('Channel:' + channame + ' <- Message: (' + str(len(text)) + ' chars)')

            if len(text) > options.Matterbot['msglength']: # Mattermost message limit
                blocks = []
                lines = text.split('\n')
                blocksize = 0
                block = ''
                for line in lines:
                    lensize = len(line)
                    if (blocksize + lensize) < options.Matterbot['msglength']:
                        blocksize += lensize
                        block += line + '\n'
                    else:
                        blocks.append(block.strip())
                        blocksize = 0
                        block = ''
                blocks.append(block.strip())
            else:
                blocks = [text]
            for block in blocks:
                self.mmDriver.posts.create_post(options={'channel_id': chanid,
                                                         'message': block,
                                                         'root_id': postid,
                                                         })
        except:
            raise

    def channame_to_chanid(self, channame, teamid=None):
        try:
            if not teamid:
                teamid = self.my_team_id
            return self.mmDriver.channels.get_channel_by_name(teamid,channame)['id']
        except:
            return None

    def chanid_to_channame(self, chanid):
        try:
            return self.mmDriver.channels.get_channel(chanid)['name']
        except:
            return None

    def chanid_to_chandisplayname(self, chanid):
        try:
            return self.mmDriver.channels.get_channel(chanid)['display_name']
        except:
            return None

    def channame_to_chandisplayname(self, channame):
        try:
            return self.chanid_to_chandisplayname(self.channame_to_chanid(channame))
        except:
            return None

    def channame_to_chaninfo(self, channame):
        if channame in self.channelmapping['nametoid']:
            return self.channelmapping['nametoid'][channame]
        else:
            try:
                chaninfo = self.mmDriver.channels.get_channel_by_name(self.my_team_id, channame)
            except Exception as e:
                log.error(f"Could not map {channame}: {e}")
                return None
            else:
                self.channelmapping['nametoid'][chaninfo['name']] = chaninfo
                self.channelmapping['idtoname'][chaninfo['id']]   = chaninfo
                return chaninfo

    def chanid_to_chaninfo(self, chanid):
        if chanid in self.channelmapping['idtoname']:
            return self.channelmapping['idtoname'][chanid]
        else:
            try:
                chaninfo = self.mmDriver.channels.get_channel(chanid)
            except Exception as e:
                log.error(f"Could not map {chanid}: {e}")
                return None
            else:
                self.channelmapping['nametoid'][chaninfo['name']] = chaninfo
                self.channelmapping['idtoname'][chaninfo['id']]   = chaninfo
                return chaninfo

    def userid_to_username(self,userid):
        try:
            return self.mmDriver.users.get_user(userid)['username']
        except:
            return None

    def isadmin(self,userid):
        try:
            userinfo = self.mmDrivers.users.get_user(userid)
            roles = [_.lower() for _ in userinfo['roles'].split()]
            if any(options.Matterbot['botadmins']) in roles or userid in options.Matterbot['botadmins']:
                return True
        except:
            return None

    def isallowed_module(self, user, module, chaninfo):
        """
        Check if we are in a channel or in a private chat
        > There are four types of channels: public channels, private channels, direct messages, and group messages.
        source: https://docs.mattermost.com/collaborate/channel-types.html
        'O' for a public channel, 'P' for a private channel, "D": Direct message channel (1:1), "G": Group message channel (group direct message)
        """
        channame = chaninfo['name']
        if chaninfo['type'] in ('O', 'P'):
            log.debug(f"Channel name: {chaninfo['name']}")
            if (channame or 'any') in self.modules[module]['settings']['CHANS']:
                return True
        elif chaninfo['type'] == 'D' and 'private' in self.modules[module]['settings']['CHANS']:
            return True
        elif chaninfo['type'] in ('D', 'G'):
            """
            Check if a user is in one of the channels that are configured in the modules 'chans'
            """
            memberlist = []
            if ('any') in self.modules[module]['settings']['CHANS']:
                return True
            for allowed_channame in self.modules[module]['settings']['CHANS']:
                try:
                    memberlist.extend([_['user_id'] for _ in self.mmDriver.channels.get_channel_members(self.channame_to_chanid(allowed_channame))])
                    if user in memberlist:
                        return True
                except:
                    # Apparently the channel does not exist; perhaps it is spelled incorrectly or otherwise a misconfiguration?
                    log.error("There is a non-existent channel set up in the bot bindings or configuration: %s" % (channame,))
        log.info(f"User {user} is not allowed to use {module} in {channame}.")
        return False


    async def bind_message(self, userid, post, params, chaninfo, rootid):
        command = post['message'].split()[0]
        chanid = post['channel_id']
        channame = chaninfo['name']
        username = self.userid_to_username(userid)
        messages = []
        if not params:
            if command in ('!map', '@map'):
                if len(self.modules):
                    chans = set()
                    if (self.my_id and userid) in channame:
                        text =  "**List of modules in direct message:**\n"
                    else:
                        text =  "**List of modules for channel: `%s`**\n" % (self.channame_to_chandisplayname(channame,))
                    text += "\n"
                    text += "\n| **Module Name** | **Available** | **Binds** | **Description** |"
                    text += "\n| :- |  :- | :- |"
                    for module in sorted(self.modules):
                        if self.isallowed_module(userid,module,chaninfo):
                            chans.add(module)
                            text += "\n| %s | **YES** | `%s` | %s |" % (module,'`, `'.join(sorted(self.modules[module]['BINDS'])),self.modules[module]['settings']['help']['DEFAULT']['desc'].replace('|','/'))
                        elif self.isadmin(userid):
                            chans.add(module)
                            text += "\n| %s | **NO** | `%s` | %s |" % (module,'`, `'.join(sorted(self.modules[module]['BINDS'])),self.modules[module]['settings']['help']['DEFAULT']['desc'].replace('|','/'))
                    text += "\n\n"
                if not len(chans):
                    text = '@' + username + ", I don't know about any commands here.\n"
                text += "*Remember that not every command works everywhere: this depends on the configuration. Modules may offer additional help if you add the subcommand.*"
                messages.append(text)
        else:
            if not self.isadmin(userid):
                log.warning("User %s attempted to use a bind command without proper authorization.") % (userid,)
                text = "@" + username + ", you do not have permission to bind commands."
            else:
                all_channel_types = [self.chanid_to_channame(_['id']) for _ in self.mmDriver.channels.get_channels_for_user(self.my_id,self.my_team_id)]
                my_channels = [_ for _ in all_channel_types if not self.my_id in _]
                if not channame in my_channels:
                    text = "@" + username + ", you cannot bind commands to direct message windows."
                else:
                    if params[0] == '*':
                        params = self.modules.keys() # Attempt to enable/disable all modules
                    for modulename in params:
                        if not modulename in self.modules:
                            text = "@" + username + ", there is no `%s` module loaded. Use one of the help commands (`%s`) to see a list of available modules." % (modulename,"`, `".join(options.Matterbot['helpcmds']))
                        elif command in ('!bind', '@bind'):
                            if channame in self.modules[modulename]['CHANS']:
                                text = "The `%s` module is already available in the `%s` channel." % (modulename,self.channame_to_chandisplayname(channame))
                            else:
                                self.modules[modulename]['CHANS'].append(channame)
                                text = "The `%s` module is now available in the `%s` channel." % (modulename,self.channame_to_chandisplayname(channame))
                        elif command in ('!unbind', '@unbind'):
                            if not channame in self.modules[modulename]['CHANS']:
                                text = "The `%s` module is not loaded in the `%s` channel." % (modulename,self.channame_to_chandisplayname(channame))
                            else:
                                self.modules[modulename]['CHANS'].remove(channame)
                                text = "The `%s` module has been removed from the `%s` channel." % (modulename,self.channame_to_chandisplayname(channame))
                        messages.append(text)
                await self.update_bindmap()
        if len(messages):
            for message in messages:
                await self.send_message(chanid, message, rootid)

    '''
    Process an incoming post. Called by handle_raw_message.
    '''
    async def handle_post(self, data: dict):
        log.debug(f"data: {data}")
        if 'sender_name' in data:
            username = data['sender_name']
        else:
            log.info("post_edited")
            # We're currently not handling users editing messages
            return
        post = json.loads(data['post'])
        userid = post['user_id']
        chanid = post['channel_id']
        chaninfo = self.chanid_to_chaninfo(chanid)
        channame = chaninfo['name']
        rootid = post['root_id'] if len(post['root_id']) else post['id']
        messagelines = post['message'].splitlines()
        # Check if the bot is allowed to respond to its own messages (see config file)
        if options.Matterbot['recursion'] or userid != self.my_id:
            message = post['message'].split() # creates a single list with all words.

            '''
            Evaluate what input is expected. This can be a single string, multiple parameters or a long text

            Rules:
            - if a single or multiple parameters are expected, evaluate if the string is of the correct type for each parameter.
            - if a free form text is expected, get all parameters until the end or until a string ends with " if the first string started with a ".
            Then start searching for next command.

            This allows for:
                I investigated IP address @ioc 1.1.1.1 but found nothing.
            and
                @chatgpt Write simple explanation of an IP address. Mention at least:
                    netblocks
                    ASN
                    IPv4 and IPv6
            '''
            
            

            tasks = dict() # maybe rename to tasks later?
            addparams = False
            quoted_text = []
            expected_types = set()
            idx = 0
            message_idx = 0
            #for idxx, word in enumerate(message):
            while message_idx < len(message):
                word = message[message_idx]
                message_idx += 1
                '''
                Search the rest of the list for a command (again), start of quoted text, a subcommand or a parameter.
                '''
                log.debug(f"Word {word} is{' not' if word not in self.binds else ''} in self.binds. addparams: {addparams}")
                if not addparams:
                    if word in self.binds:
                        # expected_types = set() # Reset the expected_type set
                        # allowed_subcommands = set()
                        idx += 1
                        tasks[idx] = {}
                        ''' Command keyword found'''

                        log.debug(f"Keyword '{word}' found. This is a keyword used by the modules {self.binds[word]}")
                        # Use precomputed type info from loaded modules instead of re-inspecting functions
                        for module_name in self.binds.get(word, []):
                            default_sub = self.modules[module_name].get('defaultcommand')
                            cmd_entry = self.modules[module_name]['commands'].get(default_sub, {})
                            annotationset = cmd_entry.get('types') or []
                            # minimal task entry expected by later logic
                            tasks[idx][module_name] = {
                                'command': word,
                                'parameters': [],
                                'options': [],
                                'subcommand': default_sub,
                                'types': annotationset
                            }
                            # expected_types.update(annotationset)
                            # allowed_subcommands.update(list(self.modules[module_name]['commands'].keys())) #XXX Has to be changed later to only allow subcommands if the keyword triggers a single module. If multiple modules are defined in self.binds the subcommands must be set there.
                        # tasks[idx]['expected_types'] = expected_types
                        # tasks[idx]['allowed_subcommands'] = allowed_subcommands

                        ''' 
                        We have made a dict 'tasks' with all the modules
                        Now looking for parameters. 
                        '''
                        addparams = True
                        log.warning(f"tasks:{tasks}")

                elif addparams:
                    # Treat the first " that preceeds a word as the start of quoted text.
                    if word.startswith('"') and word.endswith('"') and len(word) > 1 and not quoted_text:
                        # A single word quoted text
                        param_value = word[1:-1]
                        for module_name, task_entry in tasks[idx].items():
                            task_entry['parameters'].append(param_value)
                            log.warning(f"Added parameter to {module_name}({idx}): {param_value}")
                        addparams = False  # stop looking for more parameters
                    elif word.startswith('"') and not quoted_text:
                        quoted_text.append(word[1:] if len(word) > 1 else '')
                    # Only stop when the endquote prepends a word or is a single character.
                    elif word.endswith('"') and quoted_text:
                        quoted_text.append(word[:-1])  # do not add the quote character itself
                        param_value = ' '.join(quoted_text)
                        # Process the quoted text as a single parameter
                        for module_name, task_entry in tasks[idx].items():
                            task_entry['parameters'].append(param_value)
                            log.warning(f"Added parameter to {module_name}({idx}): {param_value}")
                        # stop looking for more parameters and reset quoted_text variable.
                        addparams = False
                        quoted_text = []
                    elif quoted_text:
                        quoted_text.append(word)

                    # Check if this word is a subcommand (only if no parameters yet)
                    elif any(
                        not task_entry.get('parameters') and word in self.modules[module_name]['commands']
                        for module_name, task_entry in tasks[idx].items()
                    ):
                        """If this is the first parameter, check for subcommand."""
                        for module_name, task_entry in tasks[idx].items():
                            if word in self.modules[module_name]['commands']:
                                task_entry['subcommand'] = word
                                # Update expected types for this subcommand
                                task_entry['types'] = self.modules[module_name]['commands'][word].get('types', [])
                                log.debug(f"Set subcommand for {module_name}({idx}) to {word}")
                        # Keep addparams = True so following words are treated as parameters
                    else:
                        # Expect to add a parameter: validate against all expected types
                        validparam = False
                        for module_name, task_entry in tasks[idx].items():
                            subcommand = task_entry['subcommand']
                            for Validator in self.modules[module_name]['commands'][subcommand].get('types', []):
                                try:
                                    parameter = Validator(word)
                                except ValueError:
                                    log.debug(f"Validation failed for {word} against {Validator.__name__} in {module_name}")
                                else:
                                    log.info(f"Validation succeeded for {word} against {Validator.__name__} in {module_name}")
                                    task_entry['parameters'].append(parameter)
                                    log.warning(f"Added parameter to {module_name}({idx}): {parameter} ({type(parameter)})")
                                    validparam = True
                        if not validparam:
                            log.warning(f"Failed to validate parameter {word} for any type in tasks[{idx}]")
                            if word in self.binds:
                                # Next command keyword found; stop looking for parameters for this task
                                log.info(f"Next command keyword '{word}' found while expecting parameters; stopping parameter collection for task {idx} and rewinding one step.")
                                message_idx -= 1  # rewind one step to reprocess this word as a command keyword
                            addparams = False  # stop looking for more parameters

                else:
                    log.info(f"This is very odd. \"{word}\" is not a command keyword and I am not expecting parameters.")
            
                log.warning(f"Finished making tasks: {tasks}")        
            """ End of message parsing loop """


            files = []
            log.debug(f"Check on post. Type is {type(post)}, content:{post}")
            if 'metadata' in post:
                if 'files' in post['metadata']:
                    if len(post['metadata']['files']):
                        files = post['metadata']['files']

            """
            We can have different tasks which might call serveral modules. idx is the task number but because idx is 
            already set to the last task we use sub here instead.            
            """
            with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
                log.debug(f"tasks to process: {tasks}")
                for idx in iter(tasks):
                    # NEW: reset results per task index
                    results = []

                    for module_name in tasks[idx]:
                        subcommand = tasks[idx][module_name]['subcommand']
                        log.debug(f"Processing module: {module_name} with subtasks: {tasks[idx][module_name]}, executing {subcommand}.")
                        if self.isallowed_module(userid, module_name, chaninfo):
                            try:
                                log.debug(f"Queueing module: {module_name}")
                                results.append(executor.submit(
                                    self.modules[module_name]['commands'][subcommand]['function'],
                                    tasks[idx][module_name]['parameters'],
                                    tasks[idx][module_name].get('options', []),
                                    files=files,
                                    modules=self.modules,
                                ))
                            except Exception as e:
                                text = f"An error occurred within module: {module_name}: {+str(type(e))}: {e}"
                                await self.send_message(chanid, text, rootid)

                    # Collect and process results
                    for _ in concurrent.futures.as_completed(results):
                        try:
                            result = _.result()
                            if not result:
                                continue

                            # If module returned structured data (source/responses), convert to standard 'messages' list
                            if isinstance(result, dict) and 'source' in result and 'responses' in result:
                                result = format_as_tables(result)
                            if result and 'messages' in result:
                                for message in result['messages']:
                                    text = message.get('text', '')
                                    props = message.get('props')
                                    # Handle uploads if present
                                    if 'uploads' in message:
                                        if message['uploads'] is not None:
                                            file_ids = []
                                            for upload in message['uploads']:
                                                filename = upload['filename']
                                                payload = upload['bytes']
                                                if not isinstance(payload, (bytes, bytearray)):
                                                    payload = payload.encode()
                                                file_id = self.mmDriver.files.upload_file(
                                                    channel_id=chanid,
                                                    files={'files': (filename, payload)}
                                                )['file_infos'][0]['id']
                                                file_ids.append(file_id)
                                            post_opts = {'channel_id': chanid, 'message': text, 'file_ids': file_ids}
                                            if props:
                                                post_opts['props'] = props
                                            if rootid:
                                                post_opts['root_id'] = rootid
                                            self.mmDriver.posts.create_post(options=post_opts)
                                        else:
                                            # No uploads but props may be present
                                            if props:
                                                post_opts = {'channel_id': chanid, 'message': text, 'props': props}
                                                if rootid:
                                                    post_opts['root_id'] = rootid
                                                self.mmDriver.posts.create_post(options=post_opts)
                                            else:
                                                await self.send_message(chanid, text, rootid)
                                    else:
                                        # No uploads: if there are props, create a post with props to attach the attachment
                                        if props:
                                            post_opts = {'channel_id': chanid, 'message': text, 'props': props}
                                            if rootid:
                                                post_opts['root_id'] = rootid
                                            self.mmDriver.posts.create_post(options=post_opts)
                                        else:
                                            await self.send_message(chanid, text, rootid)
                        except Exception as e:
                            text = 'A Python error occurred: '+str(type(e))+': '+str(e)
                            await self.send_message(chanid, text, rootid)

if __name__ == '__main__' :
    '''
    Interactive run from the command-line
    '''
    parser = configargparse.ArgParser(
        config_file_parser_class=configargparse.YAMLConfigFileParser,
        description='Matterbot loads modules '
                    'and sends their output '
                    'to Mattermost.',
        default_config_files=['config.yaml']
    )
    parser.add('--Matterbot', type=str, help='MatterBot configuration, as a dictionary (see YAML config)')
    parser.add('--Modules', type=str, help='Modules configuration, as a dictionary (see YAML config)')
    parser.add('-v','--debug', default=False, action='store_true', help='Enable debug mode and log to foreground')
    global options
    options, unknown = parser.parse_known_args()
    options.Matterbot = ast.literal_eval(options.Matterbot)
    options.Modules = ast.literal_eval(options.Modules)

    # Restore a simple, pre-colorlog-style logging setup
    if not options.debug:
        # Log to file in normal mode
        logging.basicConfig(
            filename=options.Matterbot['logfile'],
            level=logging.INFO,
            format='%(levelname)s - %(name)s - %(asctime)s - %(message)s'
        )
    else:
        # Log to stderr in debug mode
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(levelname)s - %(name)s - %(asctime)s - %(message)s'
        )

    log = logging.getLogger('MatterAPI')
    log.info('Starting MatterBot')
    mm = MattermostManagers()
