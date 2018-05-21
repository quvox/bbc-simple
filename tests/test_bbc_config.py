# -*- coding: utf-8 -*-
import pytest

import binascii
import sys
sys.path.extend(["../"])
from bbc_simple.core import bbclib
from bbc_simple.core.bbc_config import BBcConfig


config = None


class TestBBcConfig(object):

    def test_00_load(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        global config
        config = BBcConfig()
        print(config.get_config())
        assert config is not None

    def test_01_update(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        conf = config.get_config()
        with open(".bbc_simple/config.json", "r") as f:
            print(f.read())
        config.update_config()
        with open(".bbc_simple/config.json", "r") as f:
            print(f.read())
