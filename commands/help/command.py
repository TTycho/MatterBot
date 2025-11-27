"""
This module provides help texts and documentation for other modules.
"""
import logging
from typing import List
from core.typevalidators import Domain, IPv4, LongString, String



SERVICE_NAME = "Matterbot Help Module"



def explain(parameters: List[String], options: str = None, modules=None, *args, **kwargs) -> dict:
    """
    List all commands or give detailed help about a specific command or commands.
    """

    data = {
        "module": __package__,
        "source": 'Matterbot Help Module',
        "responses": [],
    }

    if modules is None:
        modules = kwargs.get("modules", {}) or {}

    # Build param -> list[command_info_dict] mapping
    bind_map: dict[str, list[dict]] = {}
    for module_name, mod_info in modules.items():
        binds = mod_info['settings'].get("BINDS", []) or []
        commands = mod_info.get("commands", {}) or {}
        for bind in binds:
            for command_name, cmd_entry in commands.items():
                bind_map.setdefault(bind, []).append({
                    "module": module_name,
                    "command": command_name,
                    "entry": cmd_entry,
                })

    # If no params: list all known binds as datapoints, values empty
    if parameters == []:
        logging.info("Help called without parameters.")

        response = {
            "paragraph": "Available binds",
            "preamble": """All known bind commands for this bot. Use @help [@command] to get details about a command.
A single command can trigger multiple modules.""",
            "data": [],
        }
        for bind in sorted(bind_map):
            com_mod = set()
            for command in bind_map[bind]:
                if command['module'] in com_mod:
                    continue
                response["data"].append({
                    "category": bind,
                    "subcategory": "",
                    "datapoint": "module",
                    "stix-type": "",
                    "value": command['module']
                })
                com_mod.add(command['module'])
        data["responses"].append(response)
        return data

    # For each requested parameter, explain associated modules/commands
    for param in parameters:
        if param not in bind_map:
            logging.warning(f"explain: param '{param}' not found in modules")
            continue

        # Group command infos by module so we can emit one response per module
        by_module: dict[str, list[dict]] = {}
        for cmd_info in bind_map[param]:
            by_module.setdefault(cmd_info["module"], []).append(cmd_info)

        for module_name, cmd_infos in by_module.items():
            module_doc = modules.get(module_name, {}).get("doc", "Module has no documentation")

            response = {
                # one response per module for this param
                "paragraph": f"{module_name}",
                "preamble": module_doc,
                "data": [],
            }

            for cmd_info in cmd_infos:
                command_name = cmd_info["command"]
                cmd_entry = cmd_info["entry"]
                func = cmd_entry.get("function")
                if not func:
                    logging.warning(f"explain: no function object for {module_name}.{command_name}")
                    continue

                # Derive allowed types from the precomputed 'types' entry
                allowed_types = cmd_entry.get("types", set())
                default_cmd = modules[module_name].get("defaultcommand")
                default_flag = " (default)" if command_name == default_cmd else ""

                for t in allowed_types:
                    type_name = getattr(t, "__name__", "Unnamed Type")

                    response["data"].append({
                        "category": "Subcommand",
                        "doc": cmd_info['entry'].get('doc', ''),
                        "subcategory": f"{param} {command_name}{default_flag}",
                        "datapoint": "input type",
                        "stix-type": "",
                        "value": type_name,
                    })

            data["responses"].append(response)

    return data



def modules(parameters: List[String], options: str, modules=None, *args, **kwargs) -> dict:
    """
    List all known modules and their documentation.
    """

    # Prefer explicit modules argument, fallback to kwargs
    if modules is None:
        modules = kwargs.get("modules", {}) or {}

    data = {
        "module": __package__,
        "source": SERVICE_NAME,
        "responses": [],
    }

    response = {
        "paragraph": "Available modules",
        "preamble": "Overview of loaded modules.",
        "data": [],
    }

    for module_name, mod in modules.items():
        doc = mod.get("doc", "Module has no documentation")
        response["data"].append({
            "category": "Modules",
            "subcategory": "",
            "datapoint": module_name,
            "value": doc,
        })

    data["responses"].append(response)
    return data


def extra(parameters: List[None], options: str, modules=None, *args, **kwargs) -> dict:
    """Alternate help view, kept for compatibility.

    Mirrors the older ``extra`` method but returns a structured result similar
    to :func:`help` so it can be rendered consistently.
    """

    if modules is None:
        modules = kwargs.get("modules", {}) or {}

    data = {
        "module": __package__,
        "source": SERVICE_NAME,
        "responses": [],
    }

    response = {
        "paragraph": "Available modules (compact)",
        "preamble": "List of module names and their documentation.",
        "data": [],
    }

    for module_name, mod in modules.items():
        doc = mod.get("doc", "Module has no documentation")
        response["data"].append({
            "category": "Command",
            "subcategory": "",
            "datapoint": module_name,
            "value": doc,
        })

    data["responses"].append(response)
    logging.info("Prepared help data with %d entries", len(response["data"]))

    return data




def abc(parameters: List[Domain | IPv4], options: str, channel: str, username: str, files: list, conn, *args, **kwargs):
    """Placeholder function kept for signature compatibility with older code."""
    return {
        "module": __package__,
        "source": SERVICE_NAME,
        "responses": [],
    }


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

    return {'messages': messages}

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

