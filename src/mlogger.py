__author__ = "Tejaskumar Kasundra(tejaskumar.kasundra@gmail.com)"

import logging
import os
from logging.handlers import RotatingFileHandler

__location__ = os.path.realpath(
    os.path.join(
        os.getcwd(),
        os.path.dirname(__file__)))
LOG_FILENAME = os.path.join(__location__, 'script_logs.txt')

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    '%(asctime)s - %(levelname)-8s %(filename)-12s - %(funcName)s - %(message)s',
    '%m/%d/%Y %I:%M:%S %p')

sh = logging.StreamHandler()
sh.setLevel(logging.DEBUG)
sh.setFormatter(formatter)
logger.addHandler(sh)

fh = RotatingFileHandler(
    LOG_FILENAME,
    mode='a',
    maxBytes=1024000,
    backupCount=10)
fh.setLevel(logging.DEBUG)
fh.setFormatter(formatter)
logger.addHandler(fh)
