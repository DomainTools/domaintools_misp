import pytest
import logging
import os

from domaintools_misp._version import current


@pytest.fixture
def logger():
    logger = logging.getLogger("DomainTools-Pytest")
    logger.setLevel(logging.DEBUG)
    return logger


@pytest.fixture
def query_parameters():
    q = {
        "domain": "foobar.com",
        "event_id": "734",
        "config": {
            "username": os.getenv("MISP_USERNAME"),
            "api_key": os.getenv("MISP_API_KEY"),
        },
    }

    return q


@pytest.fixture
def version():
    return current
