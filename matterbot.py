#!/usr/bin/env python3

import ast
import asyncio
import collections
import concurrent.futures
import copy
import fnmatch
import importlib.util
import json
import logging
import os
import pathlib
import sys
import configargparse
from mattermostdriver import Driver
from core.helpers import checktype

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
        self.commands = {}
        self.binds = {}
        self.channelmapping = { 'idtoname': {}, 'nametoid': {}}
        


        '''
        Bindmap should become: {'!help': ['help'], '@help': ['help'], '@bootloaders': ['bootloaders'], '@bl': ['bootloaders'], '@ioc': ['bootloaders', 'cyberthreat', 'misp', 'malpedia', 'loldrivers', 'malwarebazaar', 'ripewhois', 'lolbas', 'urlhaus', 'virustotal', 'threatfox', 'ipwhois', 'sslmate', 'gtfobins', 'bssc'], '@upi': ['unprotectit'], '@ttp': ['unprotectit'], '@cyberthreat': ['cyberthreat'], '@ct': ['cyberthreat'], '@misp': ['misp'], 'hello': ['example'], 'hi': ['example'], 'hiya': ['example'], 'howdi': ['example'], 'greetings': ['example'], '@hybridanalysis': ['hybridanalysis'], '@ha': ['hybridanalysis'], '@malpedia': ['malpedia'], '@mp': ['malpedia'], '@loldrivers': ['loldrivers'], '@ld': ['loldrivers'], '@analyze': ['analyze'], '@malwarebazaar': ['malwarebazaar'], '@mb': ['malwarebazaar'], '@alienvault': ['alienvault'], '@av': ['alienvault'], '@tlsgrab': ['tlsgrab'], '@tg': ['tlsgrab'], '@ripewhois': ['ripewhois'], '@docgen': ['docgen'], '@lolbas': ['lolbas'], '@lb': ['lolbas'], '@ewa': ['ewa'], '@urlhaus': ['urlhaus'], '@uh': ['urlhaus'], '@tweetfeed': ['tweetfeed'], '@virustotal': ['virustotal'], '@vt': ['virustotal'], '@greynoise': ['greynoise'], '@threatfox': ['threatfox'], '@tf': ['threatfox'], '@censys': ['censys'], '@snow': ['snowplough'], '@snowplough': ['snowplough'], '@sp': ['snowplough'], '@ipwhois': ['ipwhois'], '@sslmate': ['sslmate'], '@geo': ['geolookup'], '@geolookup': ['geolookup'], '@gl': ['geolookup'], '@ai': ['chatgpt'], '@openai': ['chatgpt'], '@chatgpt': ['chatgpt'], '@gpt': ['chatgpt'], '@robot': ['chatgpt'], '@qualys': ['qualys'], '@ql': ['qualys'], '@am': ['attackmatrix'], '@attackmatrix': ['attackmatrix'], '@leakix': ['leakix'], '@li': ['leakix'], '@wiki': ['wikijs'], '@wikijs': ['wikijs'], '@asnwhois': ['asnwhois'], '@asn': ['asnwhois'], '@gtfobins': ['gtfobins'], '@gb': ['gtfobins'], '@bssc': ['bssc'], '@dice': ['diceroll'], '@roll': ['diceroll'], '@shodan': ['shodan']}

        '''
        try:
            bindmap = pathlib.Path(options.Matterbot['bindmap'])
            if bindmap.is_file():
                with open(bindmap, 'r') as f:
                    self.commands = json.load(f)
                    log.info(f"loaded bindmap and populated self.commands: {self.commands}")
                    log.info(f"")
                    log.info(f"Keys are {self.commands.keys()}")
                    for module in self.commands.keys():
                        log.debug(f"Working on module {module}")
                        for bind in self.commands[module]['BINDS']:
                            if bind not in self.binds:
                                self.binds[bind] = []
                            log.info(f"adding module '{module}' to bind '{bind}'")
                            self.binds[bind].append(module)
                log.debug(f"self.binds is now: {self.binds}")
                log.info(f"Loaded existing bindmap file {options.Matterbot['bindmap']} to {self.commands}")
        except: # There is no existing command map, or it failed loading; create an empty map instead.
            pass
        # Load any new modules
        # for root, dirs, files in os.walk(modulepath):
        #     log.info(f"all modules: {fnmatch.filter(files, 'command.py')}")
        for root, dirs, files in os.walk(modulepath):
            if "command.py" in files:
                module_name = root.split('/')[-1].lower()
                module = importlib.import_module(module_name + '.' + 'command', package=module_name)

                self.commands[module_name] = {}
                self.commands[module_name]['process'] = getattr(module, 'process')

                settings = {}
                if module_name in self.commands: # What is this check for? Skip if already loaded via bindmap?
                    # Is it not better to load command modules first and then populate self.commands with 
                    # information from the bindmap?
                    log.error(f"Module name {module_name} is already read. The new module will overwrite the one first one.")
                
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
                self.commands[module_name]['settings'] = settings
                # log.debug(f"Self commands: {self.commands}")
                for bind in settings['BINDS']:
                    if bind not in self.binds:
                        self.binds[bind] = []
                    self.binds[bind].append(module_name)
            log.debug(f"Binds: {self.binds}")
        try:
            with open(options.Matterbot['bindmap'],'w') as f:
                json.dump(self.commands,f)
        except:
            log.error("An error occurred writing the bindmap file: %s" % (options.Matterbot['bindmap'],))
        
        # # Resolve function calls and update the module help
        # for root, dirs, files in os.walk(modulepath):
        #     for module in fnmatch.filter(files, "command.py"):
        #         module_name = root.split('/')[-1].lower()
        #         module = importlib.import_module(module_name + '.' + 'command')
        #         defaults = importlib.import_module(module_name + '.' + 'defaults')
        #         if hasattr(defaults, 'HELP'):
        #             HELP = defaults.HELP
        #         if 'settings.py' in files:
        #             overridesettings = importlib.import_module(module_name + '.' + 'settings')    
        #             if hasattr(overridesettings, 'HELP'):
        #                 HELP = overridesettings.HELP
        #         self.commands[module_name]['process'] = getattr(module, 'process')
        #         self.commands[module_name]['help'] = HELP

                
        # self.binds = sorted(list(set(self.binds)))

        # Start the websocket
        self.mmDriver.init_websocket(self.handle_raw_message)


    async def update_bindmap(self):
        try:
            self.bindmap = copy.deepcopy(self.commands)
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
            if (channame or 'any') in self.commands[module]['settings']['CHANS']:
                return True
        elif chaninfo['type'] == 'D' and 'private' in self.commands[module]['settings']['CHANS']:
            return
        elif chaninfo['type'] in ('D', 'G'):
            """
            Check if a user is in one of the channels that are configured in the modules 'chans'
            """
            memberlist = []
            if ('any') in self.commands[module]['settings']['CHANS']:
                return True
            for allowed_channame in self.commands[module]['settings']['CHANS']:
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
                if len(self.commands):
                    chans = set()
                    if (self.my_id and userid) in channame:
                        text =  "**List of modules in direct message:**\n"
                    else:
                        text =  "**List of modules for channel: `%s`**\n" % (self.channame_to_chandisplayname(channame,))
                    text += "\n"
                    text += "\n| **Module Name** | **Available** | **Binds** | **Description** |"
                    text += "\n| :- |  :- | :- |"
                    for module in sorted(self.commands):
                        if self.isallowed_module(userid,module,chaninfo):
                            chans.add(module)
                            text += "\n| %s | **YES** | `%s` | %s |" % (module,'`, `'.join(sorted(self.commands[module]['BINDS'])),self.commands[module]['settings']['help']['DEFAULT']['desc'].replace('|','/'))
                        elif self.isadmin(userid):
                            chans.add(module)
                            text += "\n| %s | **NO** | `%s` | %s |" % (module,'`, `'.join(sorted(self.commands[module]['BINDS'])),self.commands[module]['settings']['help']['DEFAULT']['desc'].replace('|','/'))
                    text += "\n\n"
                if not len(chans):
                    text = '@' + username + ", I don't know about any commands here.\n"
                text += "*Remember that not every command works everywhere: this depends on the configuration. Modules may offer additional help if you add the subcommand.*"
                messages.append(text)
        else:
            if not self.isadmin(userid):
                logging.warning("User %s attempted to use a bind command without proper authorization.") % (userid,)
                text = "@" + username + ", you do not have permission to bind commands."
            else:
                all_channel_types = [self.chanid_to_channame(_['id']) for _ in self.mmDriver.channels.get_channels_for_user(self.my_id,self.my_team_id)]
                my_channels = [_ for _ in all_channel_types if not self.my_id in _]
                if not channame in my_channels:
                    text = "@" + username + ", you cannot bind commands to direct message windows."
                else:
                    if params[0] == '*':
                        params = self.commands.keys() # Attempt to enable/disable all modules
                    for modulename in params:
                        if not modulename in self.commands:
                            text = "@" + username + ", there is no `%s` module loaded. Use one of the help commands (`%s`) to see a list of available modules." % (modulename,"`, `".join(options.Matterbot['helpcmds']))
                        elif command in ('!bind', '@bind'):
                            if channame in self.commands[modulename]['CHANS']:
                                text = "The `%s` module is already available in the `%s` channel." % (modulename,self.channame_to_chandisplayname(channame))
                            else:
                                self.commands[modulename]['CHANS'].append(channame)
                                text = "The `%s` module is now available in the `%s` channel." % (modulename,self.channame_to_chandisplayname(channame))
                        elif command in ('!unbind', '@unbind'):
                            if not channame in self.commands[modulename]['CHANS']:
                                text = "The `%s` module is not loaded in the `%s` channel." % (modulename,self.channame_to_chandisplayname(channame))
                            else:
                                self.commands[modulename]['CHANS'].remove(channame)
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
            
            

            messages = dict() # maybe rename to tasks later?
            addparams = False
            quoted_text = []
            expected_subcommands = set()
            # expected_types = set()
            for idx, word in enumerate(message):
                '''
                Search the rest of the list for a command again.
                '''
                log.debug(f"Word {word} is{' not' if word not in self.binds else ''} in self.binds. addparams: {addparams}")
                if addparams == False and word in self.binds: 
                    ''' First search a command '''

                    log.debug(f"Command is: {word} and used by the modules {self.binds[word]}")
                    '''
                    Now that we have a list of modules we get the expected subcommands and expected query types.
                    '''
                    for module_name in self.binds[word]:
                        messages[module_name] = {'command': word, 'parameters': [], 'options': []}

                    ''' 
                    We have made a dict with messages
                    Now looking for parameters. 
                    '''
                    addparams = True
                    logging.warning(f"Messages:{messages}")

                
                elif addparams:
                    '''
                    Evaluate what input is expected. This can be a single string, multiple parameters or a long text
                    '''
                    allowed_types = list()
                    for module_name in iter(messages):
                        log.info(f"Module: {module_name}")
                        allowed_subcommands = self.commands[module_name]['settings']['EXPECT']['subcommands'].keys()
                        
                        log.debug(f"Allowed subcommands: {allowed_subcommands}")
                        # First save a allowed types into allowed_types and set the subcommand in messages.
                        if word.lower() in allowed_subcommands:
                            allowed_types = self.commands[module_name]['settings']['EXPECT']['subcommands'][word]['types']
                            messages[module_name]['subcommand'] = word
                            log.debug(f"{word} was found in {allowed_subcommands}")
                            continue # because word was a subcommand
                        elif not 'subcommand' in messages[module_name]:
                            default_subcommand = next(iter(self.commands[module_name]['settings']['EXPECT']['subcommands']))
                            allowed_types = self.commands[module_name]['settings']['EXPECT']['subcommands'][default_subcommand]['types']
                            messages[module_name]['subcommand'] = default_subcommand
                        

                        # Treat the first " that preceeds a word as the start of quoted text.
                        if word.startswith('"') and not in_quoted_text:
                            quoted_text.append(word[1:]) if len(word) > 1 else quoted_text.append('')
                        # Only stop when the endquote prepends a word or is a single character.
                        elif word.endswith('"') and in_quoted_text:
                            quoted_text.append(word[:-1]) # do not add the quote character itself.
                            # Process the quoted text as a single parameter
                            messages[-1]['parameters'].append(' '.join(quoted_text))
                            # stop looking for more parameter and reset quoted_text variable.
                            addparams = False
                            quoted_text = []
                        elif quoted_text:
                            quoted_text.append(word)
                        # Ending dealing with quoted text
                        # word is also not a subcommand, maybe it is an options?
                        elif word.lower() in self.commands[module_name]['settings']['EXPECT']['subcommands'][messages[module_name]['subcommand']]['options']:
                            messages[module_name]['options'].append(word)
                        # Now assuming word can only be a parameter or stop listning for parameters.
                        else:
                            wordtype = checktype(word)
                            if wordtype in allowed_types:
                                messages[module_name]['parameters'].append(word)
                                messages[module_name]['type'] = wordtype
                            elif 'longstring' not in allowed_types:
                                addparams = False # But what is you have multiple lines in messages                       
                else:
                    log.info(f"\"{word}\" is not a keyword and I am not expecting parameters.")
            
            log.warning(f"Finished making tasks: {messages}")        
  
            #   log.info("---")
            #             log.info(f"Module {module_name} has settings: {self.commands[module_name].keys()}")
            #             log.info(f"Module {module_name} has subcommands: {self.commands[module_name]['EXPECT']['subcommands'].keys()}")
            #             expected_subcommands.update(self.commands[module_name]['EXPECT']['subcommands'].keys())
            #             default_subcommand = next(iter(self.commands[module_name]['EXPECT']['subcommands']))
            #             default_types  = self.commands[module_name]['EXPECT']['subcommands'][default_subcommand]['types']
            #             expected_types = default_types
            #                                     messages[module_name]['subcommand'] = default_subcommand

            #             log.info(f"Default subcommands \"{default_subcommand}\"")
            #             log.info(f"Default subcommand has types \"{default_types}\"")
            #             log.info(f"Expected types \"{expected_types}\"")
            #             log.info("---")

            # for mline in messagelines:
            #     log.warning(f"Message: {mline}")
            #     addparams = False
            #     message = mline.split() # list will all words on one line
            #     for idx,word in enumerate(message):
            #         log.debug(f"(({word in self.binds}) and ({message[idx-1] not in options.Matterbot['helpcmds']} and {message[idx-1] not in options.Matterbot['mapcmds']} ) \
            #          or ({word in options.Matterbot['helpcmds']}) or (({word in options.Matterbot['mapcmds']}) and ({message[idx-1] not in options.Matterbot['helpcmds'] }))  )")
            #         if ((word in self.binds) and (message[idx-1] not in options.Matterbot['helpcmds'] and message[idx-1] not in options.Matterbot['mapcmds'] ) # In this case hand over the word to elif \
            #              or (word in options.Matterbot['helpcmds']) or ((word in options.Matterbot['mapcmds']) and (message[idx-1] not in options.Matterbot['helpcmds'] ))  ): # word is a helpcmd or bind command
            #             messages.append({'command':word,'parameters':[]})
            #             addparams = True
            #         elif addparams:
            #             messages[-1]['parameters'].append(word)
            # log.debug(f"Messages: {messages}")

            files = []
            log.debug(f"Check on post. Type is {type(post)}, content:{post}")
            if 'metadata' in post:
                if 'files' in post['metadata']:
                    if len(post['metadata']['files']):
                        files = post['metadata']['files']
            with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
                logging.debug(f"Messages to process: {messages}")
                results = []                        
                for module_name in messages:
                    logging.debug(f"Processing module: {module_name} with messages: {messages[module_name]}")
                    if self.isallowed_module(userid, module_name, chaninfo):
                        try:
                            logging.debug(f"Queueing module: {module_name}")
                            results.append(executor.submit(self.commands[module_name]['process'], messages[module_name], channame, username, files, self.mmDriver))
                        except Exception as e:
                            text = f"An error occurred within module: {module_name}: {+str(type(e))}: {e}"
                            await self.send_message(chanid, text, rootid)

                for _ in concurrent.futures.as_completed(results):
                    logging.debug(f"Module completed: {results}")
                    try:
                        result = _.result()
                        if result and 'messages' in result:
                            for message in result['messages']:
                                if 'text' in message:
                                    text = message['text']
                                if 'uploads' in message:
                                    if message['uploads'] != None:
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
                                        self.mmDriver.posts.create_post(options={'channel_id': chanid,
                                                                                'message': text,
                                                                                'file_ids': file_ids,
                                                                                })
                                    else:
                                        await self.send_message(chanid, text, rootid)
                                else:
                                    await self.send_message(chanid, text, rootid)
                    except Exception as e:
                        text = 'A Python error occurred: '+str(type(e))+': '+str(e)
                        await self.send_message(chanid, text, rootid)

if __name__ == '__main__' :
    '''
    Interactive run from the command-line
    '''
    parser = configargparse.ArgParser(config_file_parser_class=configargparse.YAMLConfigFileParser,
                                      description='Matterbot loads modules '
                                                  'and sends their output '
                                                  'to Mattermost.',
                                                  default_config_files=['config.yaml'])
    parser.add('--Matterbot', type=str, help='MatterBot configuration, as a dictionary (see YAML config)')
    parser.add('--Modules', type=str, help='Modules configuration, as a dictionary (see YAML config)')
    parser.add('-v','--debug', default=False, action='store_true', help='Enable debug mode and log to foreground')
    global options
    options, unknown = parser.parse_known_args()
    options.Matterbot = ast.literal_eval(options.Matterbot)
    options.Modules = ast.literal_eval(options.Modules)
    if not options.debug:
        logging.basicConfig(filename=options.Matterbot['logfile'], format='%(levelname)s - %(name)s - %(asctime)s - %(message)s')
    else:
        logging.basicConfig(level=0)
    log = logging.getLogger('MatterAPI')
    log.info('Starting MatterBot')
    mm = MattermostManagers()
