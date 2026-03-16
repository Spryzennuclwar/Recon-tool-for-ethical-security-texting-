#!/usr/bin/env python3
# AresProbe v3 – Comprehensive Web Assessment Tool – March 2026
# Modified: removed credential brute-force, added login mechanism explanation

import random
import subprocess
import os
import json
import time
import re
import threading
from datetime import datetime
from urllib.parse import urlparse, urljoin
from pathlib import Path
from typing import List, Optional, Dict, Any
import requests
from bs4 import BeautifulSoup
from ipaddress import ip_address

try:
    from rich.console import Console
    from rich.prompt import Prompt
    from rich.logging import RichHandler
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    Console = type('Console', (), {'print': print})
    Prompt = type('Prompt', (), {'ask': input})

# Logging setup
import logging
from logging.handlers import RotatingFileHandler

logger = logging.getLogger("AresProbe")
logger.setLevel(logging.INFO)
console_handler = RichHandler(rich_tracebacks=True, markup=True) if HAS_RICH else logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(console_handler)
file_handler = RotatingFileHandler("aresprobe.log", maxBytes=10*1024*1024, backupCount=5)
file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(file_handler)

console = Console() if HAS_RICH else None

# Configuration
DEFAULT_CONFIG = {
    "workspace_prefix": "ARES_SCAN",
    "ffuf_wordlists": [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt",
        "/usr/share/seclists/Discovery/Web-Content/big.txt",
    ],
    "ffuf_threads": 120,
    "ffuf_recursion_depth": 3,
    "ffuf_match_codes": "200,201,204,301,302,307,401,403,500",
    "ffuf_timeout": 3600,
    "nuclei_severity": "low,medium,high,critical",
    "nuclei_tags": "cve,vuln,misconfig,exposure,http,default-login,file,fuzz,tech,iot,network",
    "nuclei_concurrency": 120,
    "nuclei_rate_limit": 300,
    "nuclei_timeout": 7200,
    "sqlmap_level": 5,
    "sqlmap_risk": 3,
    "sqlmap_threads": 10,
    "sqlmap_timeout": 14400,
    "http_timeout": 20,
    "tool_global_fallback_timeout": 28800,
}

# Periodic progress reporter
class PeriodicStats:
    def __init__(self, name: str, interval: int = 7):
        self.name = name
        self.interval = interval
        self.start_time = time.time()
        self.counter = 0
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def inc(self, by: int = 1):
        with self._lock:
            self.counter += by

    def start(self):
        if self._thread is not None:
            return
        self._stop_event.clear()
        self.start_time = time.time()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=1.0)
            self._thread = None

    def _run(self):
        while not self._stop_event.is_set():
            elapsed = time.time() - self.start_time
            rate = self.counter / elapsed if elapsed > 0.1 else 0
            logger.info(
                f"[PROGRESS] {self.name} | "
                f"processed: {self.counter} | "
                f"elapsed: {elapsed:.0f}s | "
                f"rate: {rate:.1f}/s"
            )
            time.sleep(self.interval)

# Main scanning class
class AresProbe:
    def __init__(self, target_url: str, proxy: Optional[str] = None, config: Optional[Dict[str, Any]] = None):
        target_url = target_url.strip().rstrip("/")
        if not target_url.startswith(("http://", "https://")):
            raise ValueError("Target must start with http:// or https://")
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.proxy = proxy.strip() if proxy and proxy.strip() else None
        self.proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
        self.config = {**DEFAULT_CONFIG, **(config or {})}
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.workspace = Path(f"{self.config['workspace_prefix']}_{self.domain}_{ts}")
        self.evidence_dir = self.workspace / "evidence"
        self.tools_dir = self.workspace / "tools"
        self.findings_file = self.workspace / "findings.json"
        self.findings: Dict[str, Any] = {
            "origin_ips": [],
            "interesting_paths": [],
            "login_detected": False,
            "login_url": None,
            "login_form_info": None,
            "login_mechanism_notes": "",
            "sqli_indicators": [],
            "notes": []
        }
        self._init_dirs()

    def _init_dirs(self) -> None:
        for d in (self.workspace, self.evidence_dir, self.tools_dir):
            d.mkdir(parents=True, exist_ok=True)
        logger.info("Workspace created: %s", self.workspace)

    # (rest of methods remain the same, only minor fixes applied)
    @staticmethod
    def _is_valid_ip(s: str) -> bool:
        try:
            ip = ip_address(s)
            return not ip.is_private and not ip.is_loopback and not ip.is_multicast
        except ValueError:
            return False

# Entry point
if __name__ == "__main__":
    if console:
        console.print("[bold blue]AresProbe v3 – Comprehensive Web Assessment Tool (no brute-force)[/bold blue]")
    else:
        print("AresProbe v3 – Comprehensive Web Assessment Tool (no brute-force)")
    target = Prompt.ask("Target URL", default="https://example.com").strip()
    proxy = Prompt.ask("Proxy (http/socks5) – optional", default="").strip() or None
    probe = AresProbe(target_url=target, proxy=proxy)
    try:
        probe.run()
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user – partial results saved")
    except Exception as e:
        logger.error("Unexpected error during execution", exc_info=True)
