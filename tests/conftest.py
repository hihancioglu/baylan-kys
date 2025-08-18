import os
import sys
import importlib
from pathlib import Path

import pytest


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    repo_root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(repo_root))
    sys.path.insert(0, str(repo_root / "portal"))

    db_path = repo_root / "test.db"
    if db_path.exists():
        db_path.unlink()
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"

    models = importlib.import_module("models")
    models.Base.metadata.create_all(bind=models.engine)

    yield

    models.Base.metadata.drop_all(bind=models.engine)


@pytest.fixture(autouse=True)
def reset_database():
    m = importlib.import_module("models")
    m.Base.metadata.drop_all(bind=m.engine)
    m.Base.metadata.create_all(bind=m.engine)
    yield
