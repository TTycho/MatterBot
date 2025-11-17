import os
import fnmatch
import importlib
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Define the module path
modulepath = 'commands'

# Initialize a dictionary to store module settings
debug_module_settings = {}

# Walk through the module directory
for root, dirs, files in os.walk(modulepath):
    logging.debug(f"Dirs: {dirs}")

    for module in fnmatch.filter(files, "command.py"):
        module_name = root.split('/')[-1].lower()
        module = importlib.import_module(modulepath + '.' + module_name + '.' + 'command')

        logging.debug(f"Processing: {module}")
        logging.debug(f"Processing module: {module_name}")

        module.settings = {}
        # Import defaults and update settings with defaults
        try:
            defaults = importlib.import_module(modulepath + '.' + module_name + '.' + 'defaults')
            logging.debug(f"Imported defaults for module: {module_name}: {defaults}")
            module.settings.update({k: v for k, v in defaults.__dict__.items() if not k.startswith('__')})
            logging.debug(f"Updated settings with defaults for module: {module_name}")
        except ImportError as e:
            logging.error(f"Failed to import defaults for module {module_name}: {e}")

        try:
            overridesettings = importlib.import_module(modulepath + '.' + module_name + '.' + 'settings')
            logging.debug(f"Imported settings for module: {module_name}")
            module.settings.update({k: v for k, v in overridesettings.__dict__.items() if not k.startswith('__')})
            logging.debug(f"Updated settings with overrides for module: {module_name}")
        except ImportError as e:
            logging.debug(f"No settings.py found for module {module_name}: {e}")

        # Store the settings in the debug dictionary
        debug_module_settings[module_name] = module.settings
        logging.debug(f"Stored settings for module: {module_name} in debug_module_settings:\n{module.settings}")

# Log the final debug_module_settings
logging.debug(f"Final debug_module_settings: {debug_module_settings}")