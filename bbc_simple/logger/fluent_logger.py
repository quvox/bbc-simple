from io import BytesIO
from logging import config, getLogger

import msgpack
import yaml

import os
import sys
import faulthandler


def initialize_logger(conf_filename):
    """read config file"""
    with open(conf_filename) as f:
        conf = yaml.load(f)
    """setup globally"""
    config.dictConfig(conf["logging"])


def setup_and_send_crash_log(crash_logfile='/tmp/crash.log'):
    if os.path.exists(crash_logfile) and os.path.getsize(crash_logfile) > 50:
        with open(crash_logfile) as f:
            errorlog = f.read()
            logger = getLogger("crash_report")
            logger.fatal({"crash": errorlog})
    if os.path.exists(crash_logfile):
        os.remove(crash_logfile)
    fd = os.open(crash_logfile, os.O_WRONLY | os.O_CREAT)
    os.dup2(fd, sys.stderr.fileno())
    faulthandler.enable()


def overflow_handler(pendings):
    unpacker = msgpack.Unpacker(BytesIO(pendings))
    for unpacked in unpacker:
        print(unpacked)
