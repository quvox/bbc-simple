# -*- coding: utf-8 -*-
"""
Copyright (c) 2018 quvox.net

This code is based on that in bbc-1 (https://github.com/beyond-blockchain/bbc_simple)
"""
import os
import json
import copy
from collections import Mapping

import sys
sys.path.extend(["../../"])
from bbc_simple.core import bbclib


DEFAULT_WORKING_DIR = '.bbc_simple'
DEFAULT_CONFIG_FILE = 'config.json'
DEFAULT_CORE_PORT = 9000

TIMEOUT_TIMER = 3

current_config = {
    'workingdir': DEFAULT_WORKING_DIR,
    'client': {
        'port': DEFAULT_CORE_PORT,
    },
    'redis': {
        'host': "localhost",
        'port': 6379,
    },
    'db': {
        "db_type": "mysql",
        "db_addr": "127.0.0.1",
        "db_port": 3306,
        "db_user": "user",
        "db_pass": "pass",
        "db_rootpass": "password",
    },
    'domains': {
    },
}


def update_deep(d, u):
    """Utility for updating nested dictionary"""
    for k, v in u.items():
        # this condition handles the problem
        if not isinstance(d, Mapping):
            d = u
        elif isinstance(v, Mapping):
            r = update_deep(d.get(k, {}), v)
            d[k] = r
        else:
            d[k] = u[k]
    return d


class BBcConfig:
    """System configuration"""
    def __init__(self, directory=None, file=None):
        self.config = copy.deepcopy(current_config)
        if directory is not None:
            self.working_dir = directory
            self.config['workingdir'] = self.working_dir
        else:
            self.working_dir = self.config['workingdir']
        if file is not None:
            self.config_file = file
        else:
            self.config_file = os.path.join(self.working_dir, DEFAULT_CONFIG_FILE)

        if not os.path.exists(self.working_dir):
            os.mkdir(self.working_dir)

        if os.path.isfile(self.config_file):
            update_deep(self.config, self.read_config())
        self.update_config()

    def read_config(self):
        """Read config file"""
        config = dict()
        with open(self.config_file, "r") as f:
            try:
                config = json.load(f)
            except:
                print("config file must be in JSON format")
                os._exit(1)
        return config

    def update_config(self):
        """Write config to file (config.json)"""
        try:
            with open(self.config_file, "w") as f:
                json.dump(self.config, f, indent=4)
            return True
        except:
            import traceback
            traceback.print_exc()
            return False

    def get_json_config(self):
        """Get config in json format"""
        self.update_config()
        return json.dumps(self.config, indent=2)

    def get_config(self):
        """Return config dictionary"""
        return self.config

    def get_domain_config(self, domain_id, create_if_new=False):
        """Return the part of specified domain_id in the config dictionary"""
        domain_id_str = bbclib.convert_id_to_string(domain_id)
        conf = self.read_config()
        if 'domains' in conf and domain_id_str in conf['domains']:
            self.config['domains'][domain_id_str] = conf['domains'][domain_id_str]
            return self.config['domains'][domain_id_str]
        if create_if_new and domain_id_str not in self.config['domains']:
            self.config['domains'][domain_id_str] = conf['db']  # default セッティング
            return self.config['domains'][domain_id_str]
        return None

    def remove_domain_config(self, domain_id):
        """Remove the part of specified domain_id in the config dictionary"""
        domain_id_str = bbclib.convert_id_to_string(domain_id)
        if domain_id_str in self.config['domains']:
            del self.config['domains'][domain_id_str]
            self.update_config()

