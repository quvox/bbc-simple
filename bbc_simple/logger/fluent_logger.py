from io import BytesIO
from logging import config, getLogger

import msgpack
import yaml


def get_fluent_logger(conf_filename='logconf.yml', name=''):
    """
    :param conf_filename:
    :param name:
    :return:
    """
    """read config file"""
    with open(conf_filename) as f:
        conf = yaml.load(f)
    """setup globally"""
    config.dictConfig(conf["logging"])
    return getLogger(name)


def overflow_handler(pendings):
    unpacker = msgpack.Unpacker(BytesIO(pendings))
    for unpacked in unpacker:
        print(unpacked)
