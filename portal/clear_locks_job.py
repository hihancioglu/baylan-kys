"""Cron job to clear expired document locks."""
from services import clear_expired_locks


def run() -> None:
    clear_expired_locks()


if __name__ == "__main__":
    run()
