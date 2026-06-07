import os
import logging
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

REQUIRED_KEYS = ["ANTHROPIC_API_KEY"]

def check_keys():
    missing = [k for k in REQUIRED_KEYS if not os.getenv(k)]
    if missing:
        raise SystemExit(f"Missing required env keys: {', '.join(missing)}")

MODEL = "claude-sonnet-4-6"
MAX_TOKENS = 4096
MAX_ITERATIONS = 10

def setup_loggers() -> tuple:
    """Return (agent_log, tool_log) — two isolated file loggers, one per session."""
    os.makedirs("logs", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    fmt = logging.Formatter("%(asctime)s  %(message)s", datefmt="%H:%M:%S")

    def _make(name: str, path: str) -> logging.Logger:
        log = logging.getLogger(name)
        log.setLevel(logging.DEBUG)
        log.propagate = False
        fh = logging.FileHandler(path, encoding="utf-8")
        fh.setFormatter(fmt)
        log.addHandler(fh)
        return log

    agent_log = _make(f"phish.agent.{timestamp}", f"logs/agent_{timestamp}.log")
    tool_log  = _make(f"phish.tools.{timestamp}", f"logs/tools_{timestamp}.log")

    print(f"Logging to  logs/agent_{timestamp}.log  |  logs/tools_{timestamp}.log")
    return agent_log, tool_log
