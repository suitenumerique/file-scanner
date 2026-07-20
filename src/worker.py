"""Single entrypoint for the dramatiq worker, configured via environment.

Adapted from suitenumerique/st-home. Production (Procfile) and local development
(docker compose) both run ``python -m worker`` so there is one place that
defines how the worker starts. It wraps the dramatiq CLI: importing the broker
module configures the global broker, and the task modules register the actors
the worker runs.

Environment variables (WORKER_*, broker-agnostic so the implementation can be
swapped without renaming configuration):
    WORKER_PROCESSES   worker processes to fork (default "2")
    WORKER_THREADS     threads per process (default "8")
    WORKER_QUEUES      space-separated queues to consume (default "default")
    WORKER_WATCH       path to watch for code changes and auto-reload
                       (e.g. "." in local dev; leave unset in production)
"""

import os
import sys

from dramatiq.cli import main, make_argument_parser

# First positional must be the broker module (it sets the global broker); the
# rest are imported so their actors get registered.
BROKER_MODULE = "broker"
TASK_MODULES = ["tasks"]


def build_argv():
    argv = [
        BROKER_MODULE,
        *TASK_MODULES,
        "--processes",
        os.getenv("WORKER_PROCESSES", "2"),
        "--threads",
        os.getenv("WORKER_THREADS", "8"),
    ]
    watch = os.getenv("WORKER_WATCH")
    if watch:
        argv += ["--watch", watch]
    # --queues takes a variable number of values, so keep it last.
    argv += ["--queues", *os.getenv("WORKER_QUEUES", "default").split()]
    return argv


if __name__ == "__main__":
    from scanner import validate_registry

    validate_registry()  # fail fast on an inconsistent category/scanner config
    sys.exit(main(make_argument_parser().parse_args(build_argv())))
