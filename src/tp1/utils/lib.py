
from scapy.all import get_if_list

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
    print("Interfaces disponibles :", get_if_list())
    interface = input("Nom de l'interface : ")
    return interface
