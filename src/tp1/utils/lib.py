
from scapy.all import get_if_list
from tp1.utils.config import logger

def hello_world() -> str:
    """
    Hello world function

    :return: "hello world"
    """
    return "hello world"


def choose_interface() -> str:
    """
    Return network interface and input user choice

    :return: network interface
    """
    logger.info("Interfaces disponibles : %s", get_if_list())
    interface = input("Nom de l'interface : ")
    return interface
