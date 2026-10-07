import os
import tempfile

_tmp = tempfile.mkdtemp()
os.environ.update({
    "DATABASE_URL": f"sqlite:///{_tmp}/test.db",
    "MODEL_PATH": f"{_tmp}/clf.joblib",
    "SCAMSHIELD_NETWORK": "0",      # tests never touch the network
    "ADMIN_API_KEYS": "admin-key",
    "API_KEYS": "user-key",
    "RATE_LIMIT_PER_MINUTE": "1000",
})

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c
