from unittest.mock import patch

from src.tp1.utils.lib import choose_interface, hello_world


def test_when_hello_world_then_return_hello_world():
    assert hello_world() == "hello world"


def test_choose_interface_returns_user_input():
    with patch("builtins.input", return_value="eth0"):
        with patch("src.tp1.utils.lib.get_if_list", return_value=["lo", "eth0"]):
            result = choose_interface()
    assert result == "eth0"