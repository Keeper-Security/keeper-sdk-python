import logging

from keepersdk import utils


def get_logger() -> logging.Logger:
    return utils.get_logger('keeper.commander')

