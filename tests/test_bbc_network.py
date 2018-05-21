# -*- coding: utf-8 -*-
import pytest

import shutil
import queue
import time

import os
import sys
sys.path.extend(["../"])

from bbc_simple.core import bbclib
from bbc_simple.core import bbc_network, bbc_config, query_management, bbc_stats

LOGLEVEL = 'debug'
LOGLEVEL = 'info'

ticker = query_management.get_ticker()
core_nodes = 10
networkings = [None for i in range(core_nodes)]
nodes = [None for i in range(core_nodes)]

domain_id = bbclib.get_new_id("test_domain")
asset_group_id = bbclib.get_new_id("asset_group_1")
users = [bbclib.get_new_id("test_user_%i" % i) for i in range(core_nodes)]

result_queue = queue.Queue()

sample_resource_id = bbclib.get_new_id("sample_resource_id")


def get_random_data(length=16):
    import random
    source_str = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return "".join([random.choice(source_str) for x in range(length)])


class DummyCore:
    class UserMessageRouting:
        def add_domain(self, domain_id):
            pass

        def remove_domain(self, domain_id):
            pass

    def __init__(self):
        self.user_message_routing = DummyCore.UserMessageRouting()
        self.stats = bbc_stats.BBcStats()


class TestBBcNetwork(object):

    def test_01_start(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        dummycore = DummyCore()
        global networkings, nodes, conf
        for i, nw in enumerate(networkings):
            if os.path.exists(".bbc1-%d"%i):
                shutil.rmtree(".bbc1-%d"%i)
            config = bbc_config.BBcConfig(directory=".bbc1-%d"%i)
            networkings[i] = bbc_network.BBcNetwork(core=dummycore, config=config)
            networkings[i].create_domain(domain_id=domain_id)
            nodes[i] = networkings[i].domains[domain_id]['node_id']
            assert nodes[i] is not None

    def test_02_leave_domain(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        networkings[core_nodes-1].remove_domain(domain_id)
        print("-- wait 5 seconds --")
        time.sleep(5)


if __name__ == '__main__':
    pytest.main()
