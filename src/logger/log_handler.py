import logging
import sys



def file_logger(name, path):
    """
    logs to specified file, takes name of logger usually __name__
    which refers to the name of file being run from and path which
    is the path to log to with filename ex> path\\to\\file.log
    """
    file_formatter = logging.Formatter('%(asctime)s~%(levelname)s~%(message)s')
    file_handler = logging.FileHandler(path)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(file_formatter)
    logger = logging.getLogger(name)
    logger.addHandler(file_handler)
    logger.setLevel(logging.INFO)
    return logger


def console_logger(name):
    """
    handles sending msg' to the console
    """
    console_formatter = logging.Formatter('%(asctime)s~%(levelname)s - %(message)s')
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(console_formatter)
    logger = logging.getLogger(name)
    logger.addHandler(console_handler)
    logger.setLevel(logging.INFO)
    return logger


def build_logger(name,path):
    console_formatter = logging.Formatter('%(asctime)s~%(levelname)s - %(message)s')
    console_handler = logging.StreamHandler(stream=sys.stdout)
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(console_formatter)
    file_formatter = logging.Formatter('%(asctime)s~%(levelname)s~%(message)s')
    file_handler = logging.FileHandler(path)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(file_formatter)
    logger = logging.getLogger(name)
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    logger.setLevel(logging.INFO)
    pass