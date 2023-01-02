#!/usr/bin/env python3

import logging
import os
import sys
import fnmatch
import importlib.util
import configargparse
import ast
import asyncio
import json

from mattermostdriver import Driver

class TokenAuth():
    def __call__(self, r):
        r.headers['Authorization'] = "Bearer %s" % options.Matterbot['password']
        r.headers['X-Requested-With'] = 'XMLHttpRequest'
        return r

class MattermostManager(object):
    def __init__(self):
        self.mmDriver = Driver(options={
            'url'       : options.Matterbot['host'],
            'port'      : options.Matterbot['port'],
            'login_id'  : options.Matterbot['username'],
            'token'     : options.Matterbot['password'],
            'auth'      : TokenAuth,
            #'debug'     : options.debug,
            'basepath'  : '/api/v4',
            'keepalive' : True,
            'keepalive_delay': 30,
            'scheme'    : 'https',
            'websocket_kw_args': {'ping_interval': 5},
        })
        self.mmDriver.login()
        self.me = self.mmDriver.users.get_user( user_id='me' )
        self.my_team_id = self.mmDriver.teams.get_team_by_name(options.Matterbot['teamname'])['id']

        # Create the channel map
        self.channel_ids = {}
        for channel in options.Matterbot['channelmap']:
            channelname = channel.lower()
            self.channel_ids[channelname] = self.mmDriver.channels.get_channel_by_name(self.my_team_id, options.Matterbot['channelmap'][channelname])['id']

        # Map all the commands to their modules
        self.commands = {}
        modulepath = options.Modules['commanddir'].strip('/')
        sys.path.append(modulepath)
        for root, dirs, files in os.walk(modulepath):
            for module in fnmatch.filter(files, "command.py"):
                module_name = root.split('/')[-1].lower()
                module = importlib.import_module(module_name + '.' + 'command')
                self.commands[module_name] = {'binds': module.settings.BINDS, 'chans': module.settings.CHANS, 'process': getattr(module, 'process')}
        # Start the websocket
        self.mmDriver.init_websocket(self.handle_raw_message)

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
            print(('ERROR'), e)

    async def send_message(self, channel, content):
        try:
            channelname = channel.lower()
            await self.mmDriver.posts.create_post( options={'channel_id': channel,
                                                            'message': content,
                                                            })
        except:
            return

    async def handle_post(self, data: dict):
        my_id = self.me['id']
        username = data['sender_name']
        post = json.loads(data['post'])
        userid = post['user_id']
        channelinfo = self.mmDriver.channels.get_channel(post['channel_id'])
        userchannels = [i['name'] for i in self.mmDriver.channels.get_channels_for_user(userid, self.my_team_id)]
        channelname = channelinfo['name']
        channelid = channelinfo['id']
        message = post['message'].split(' ')
        commands = set()
        if userid != my_id:
            command = message[0].lower()
            try:
                params = message[1:]
            except IndexError:
                params = None
            for module in self.commands:
                for chan in self.commands[module]['chans']:
                    if channelname == chan or (((my_id and userid) in channelname) and chan in userchannels):
                        if command == '!help' and not params:
                            for bind in self.commands[module]['binds']:
                                commands.add('`' + bind + '`')
                        if command in self.commands[module]['binds']:
                            result = await self.commands[module]['process'](self.mmDriver, channelname, username, params)
                            if result:
                                await self.send_message(channelid, result)
            if command == '!help' and not params:
                result = username + " I know about: `!help`, " + ', '.join(commands) + " here. Remember that not every command works everywhere: this depends on the configuration. Modules may offer additional help via `!help <command>`."
                await self.send_message(channelid, result)

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
    parser.add('--debug', default=False, action='store_true', help='Enable debug mode and log to foreground')
    options, unknown = parser.parse_known_args()
    options.Matterbot = ast.literal_eval(options.Matterbot)
    options.Modules = ast.literal_eval(options.Modules)

    if not options.debug:
        logging.basicConfig(filename=options.Matterbot['logfile'], format='%(levelname)s - %(name)s - %(asctime)s - %(message)s')
    else:
        logging.basicConfig(format='%(levelname)s - %(name)s - %(asctime)s - %(message)s')
    log = logging.getLogger( 'MatterAPI' )
    log.info('Starting MatterAPI')
    mm = MattermostManager()
    modules = mm.loadCommands()
    mm.startWebsocket()
