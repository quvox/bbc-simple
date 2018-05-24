# -*- coding: utf-8 -*-
import pytest

import requests
import binascii
import threading
import time
import shutil

import sys
sys.path.extend(["../"])
from bbc_simple.core import bbclib
from bbc_simple.core.message_key_types import KeyType
from bbc_simple.core.bbc_error import *
from bbc_simple.core import bbc_app
from testutils import prepare, start_core_thread
import bbc_simple.app.bbc_admin_app_rest as bbc_rest

LOGLEVEL = 'debug'
LOGLEVEL = 'info'

core_num = 1
client_num = 1
domain_id = bbclib.get_new_id("testdomain")
asset_group_id = bbclib.get_new_id("asset_group_1")

BASE_URL = "http://localhost:3000"


def start_server():
    bbc_rest.start_server()


class TestBBcAppClient(object):

    def test_00_setup(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        shutil.rmtree(".bbc1-9000")
        prepare(core_num=core_num, client_num=client_num)
        for i in range(core_num):
            start_core_thread(index=i)
        time.sleep(1)
        th = threading.Thread(target=start_server)
        th.setDaemon(True)
        th.start()
        time.sleep(1)

    def test_01_creat_domain(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        parameter = {
            'domain_id': domain_id.hex()
        }
        req = requests.post(BASE_URL+'/domain_setup',
                            json=parameter,
                            headers={u'Content-Type': u'application/json'})
        assert req.status_code == 200
        print("response:", req.json())

    def test_02_node_id(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        req = requests.get(BASE_URL+'/get_node_id/'+domain_id.hex())
        assert req.status_code == 200
        print("response:", req.json())

    def test_03_get_config(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        req = requests.get(BASE_URL+'/get_bbc_config')
        assert req.status_code == 200
        print("response:", req.json())

    def test_04_get_stats(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        req = requests.get(BASE_URL+'/get_stats')
        assert req.status_code == 200
        print("response:", req.json())

    def test_05_get_domain_list(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        req = requests.get(BASE_URL+'/get_domain_list')
        assert req.status_code == 200
        print("response:", req.json())

    def test_06_get_user_list(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        req = requests.get(BASE_URL+'/get_user_list/'+domain_id.hex())
        assert req.status_code == 200
        print("response:", req.json())

    def test_08_get_notification_list(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        req = requests.get(BASE_URL+'/get_notification_list/'+domain_id.hex())
        assert req.status_code == 200
        print("response:", req.json())

    def test_09_close_domain(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        req = requests.get(BASE_URL+'/domain_close/'+domain_id.hex())
        assert req.status_code == 200
        print("response:", req.json())


if __name__ == '__main__':
    pytest.main()

