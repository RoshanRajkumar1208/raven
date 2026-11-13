import os
import socket

import pytest

from raven_api.demo.server import start

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(ROOT, "examples")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def demo():
    """The demo API on a random free port. The 'slow' endpoint sleeps 0.3 s."""
    port = _free_port()
    httpd = start(port=port, slow_seconds=0.3)
    httpd.base = f"http://127.0.0.1:{port}"
    httpd.seen = httpd.RequestHandlerClass.seen
    yield httpd
    httpd.shutdown()


@pytest.fixture
def example():
    return lambda name: os.path.join(EXAMPLES, name)
