from io import BytesIO
from logging import config

import os
import msgpack
import yaml

current_dir = os.path.abspath(os.path.dirname(__file__))


def initialize_logger(conf_filename=""):
    """read config file"""
    if conf_filename == "":
        conf_filename = os.path.join(current_dir, "logconf.yml")
    with open(conf_filename) as f:
        conf = yaml.load(f)
    """setup globally"""
    config.dictConfig(conf["logging"])


def overflow_handler(pendings):
    unpacker = msgpack.Unpacker(BytesIO(pendings))
    for unpacked in unpacker:
        print(unpacked)
