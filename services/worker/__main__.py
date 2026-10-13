from core.config import validate_settings_or_exit


def main():
    validate_settings_or_exit()
    # jobs.py constructs Settings at import; must stay below the guard.
    from services.worker.jobs import WorkerSettings
    from services.worker.supervise import run_forever

    # Reconnects (with backoff) when Redis goes away instead of exiting.
    run_forever(WorkerSettings)


if __name__ == "__main__":
    main()
