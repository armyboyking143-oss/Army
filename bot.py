#!/usr/bin/env python3
"""
wtr-lab.com -> EPUB Telegram bot (v3)

Flow: novel link -> pick range / Custom / Auto EPUB -> EPUB files.

v3 changes:
  * Default admin id 8049392574 (ADMIN_IDS env still overrides)
  * "Custom" button: type any range (e.g. 20-30) -> only that range
  * "Auto EPUB" button: 25 / 50 / 100 / Custom -> whole novel split into
    equal EPUBs (1-20, 21-40, 41-60 ...), each sent as soon as it is built
  * File name: [ 01-20 ] Novel Title.epub  (numbers = real chapters inside)
  * Fixed: BLOCK_COOLDOWNS doc/default mismatch, memory use (send per EPUB),
    resume keeps the same bucket alignment

ENV:
  BOT_TOKEN (required - keep it in env, never in code)
  PORT, WORKERS(2), REQUEST_DELAY(3.0), MAX_JOBS(1),
  BLOCK_COOLDOWNS(30,90,240), RETRY_DELAYS(25,25,25,40,80),
  MAX_CHAPTERS(3000), ADMIN_IDS, WTR_AES_KEY, WTR_COOKIE, WTR_USER_AGENT,
  USE_CURL(1), IMPERSONATE(chrome), KEEPALIVE_URL
"""
import asyncio
import base64
import io
import json
import logging
import os
import random
import re
import threading
import time
import uuid
import zipfile
from datetime import datetime, timezone
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.error import BadRequest, RetryAfter
from telegram.ext import (Application, CallbackQueryHandler, CommandHandler,
                          ContextTypes, MessageHandler, filters)

try:
    from curl_cffi.requests import AsyncSession as CurlSession
except Exception:  # noqa
    CurlSession = None

logging.basicConfig(format="%(asctime)s %(levelname)s %(name)s: %(message)s",
                    level=logging.INFO)
for _n in ("httpx", "httpcore", "telegram.ext.Application"):
    logging.getLogger(_n).setLevel(logging.WARNING)
log = logging.getLogger("wtrbot")


def _ints(s):
    return [int(x) for x in (s or "").replace(" ", "").split(",") if x.strip().lstrip("-").isdigit()]


BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
PORT = int(os.environ.get("PORT", "10000"))
WORKERS = max(1, int(os.environ.get("WORKERS", "2")))
REQUEST_DELAY = float(os.environ.get("REQUEST_DELAY", "3.0"))
MAX_JOBS = max(1, int(os.environ.get("MAX_JOBS", "1")))
AES_KEY = os.environ.get("WTR_AES_KEY", "IJAFUUxjM25hyzL2AZrn0wl7cESED6Ru").encode()
COOKIE_FILE = os.environ.get("COOKIE_FILE", "cookie.txt")
ADMIN_FILE = "admin.txt"
PROXY = os.environ.get("WTR_PROXY", "").strip() or None
COOKIE_TAG = "WTRCOOKIE:"
COOKIE = os.environ.get("WTR_COOKIE", "")
try:
    with open(COOKIE_FILE, encoding="utf-8") as _f:
        COOKIE = _f.read().strip() or COOKIE
except OSError:
    pass
DEFAULT_ADMIN = 8049392574
ADMIN_IDS = set(_ints(os.environ.get("ADMIN_IDS", ""))) or {DEFAULT_ADMIN}
USE_CURL = os.environ.get("USE_CURL", "1") == "1"
IMPERSONATE = os.environ.get("IMPERSONATE", "chrome")
BASE = "https://wtr-lab.com"
TG_FILE_LIMIT = 49 * 1024 * 1024
UA = os.environ.get("WTR_USER_AGENT") or (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
RETRY_DELAYS = _ints(os.environ.get("RETRY_DELAYS", "25,25,25,40,80"))
BLOCK_COOLDOWNS = _ints(os.environ.get("BLOCK_COOLDOWNS", "30,90,240"))
MAX_CHAPTERS = int(os.environ.get("MAX_CHAPTERS", "3000"))
MAX_IMG_BYTES = 40 * 1024 * 1024
CACHE_MAX = 2500
URL_RE = re.compile(r"wtr-lab\.com/([a-z]{2}(?:-[a-z]{2})?)/novel/(\d+)/([^/?#\s]+)", re.I)
RANGE_RE = re.compile(r"^\s*(\d+)\s*(?:-|–|to)\s*(\d+)\s*$", re.I)


# ----------------------------------------------------------------- errors
class ChapterLocked(Exception):
    """Chapter is not AI translated."""


class Blocked(Exception):
    """Turnstile / 1401 / 403 - rate limit or bot check."""


class EmptyChapter(Exception):
    """Server returned no body (retryable)."""


class BadKey(Exception):
    """AES decryption failed - key rotated."""


_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff]")


def esc(x):
    return escape(_CTRL.sub("", str(x)))


# ------------------------------------------------- pure helpers
def _usable(v):
    return isinstance(v, (list, str)) and len(v) > 0


def find_body_container(j):
    try:
        d = j["data"]["data"]
        if isinstance(d, dict) and _usable(d.get("body")):
            return d
    except (KeyError, TypeError):
        pass

    def walk(o, depth):
        if not isinstance(o, (dict, list)) or depth > 6:
            return None
        if isinstance(o, dict) and _usable(o.get("body")):
            return o
        vals = o[:10] if isinstance(o, list) else list(o.values())
        for v in vals:
            f = walk(v, depth + 1)
            if f is not None:
                return f
        return None

    return walk(j, 0)


def parse_content_response(text, reader_json):
    text = (text or "").strip()
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = text
    if isinstance(parsed, (str, list)):
        data = ((reader_json or {}).get("data") or {}).get("data") or {}
        return {"data": {"data": {**data, "body": parsed}}}
    c = find_body_container(parsed)
    if c is not None:
        return {"data": {"data": c}}
    return parsed


def decrypt_text(enc, key=None):
    key = key or AES_KEY
    is_arr = enc.startswith("arr:")
    if not is_arr and not enc.startswith("str:"):
        return [enc]
    parts = enc[4:].split(":")
    if len(parts) != 3:
        raise ValueError("invalid encrypted body format")
    iv, tag, ct = (base64.b64decode(p) for p in parts)
    plain = AESGCM(key).decrypt(iv, ct + tag, None).decode("utf-8")
    dec = json.loads(plain) if is_arr else plain
    return [str(x) for x in dec] if isinstance(dec, list) else [str(dec)]


def story_terms_from(js):
    out = {}
    for g in (js or {}).get("glossaries") or []:
        for t in ((g or {}).get("data") or {}).get("terms") or []:
            if isinstance(t, list) and len(t) > 1 and t[0]:
                first = t[0][0] if isinstance(t[0], list) else t[0]
                out[t[1]] = first
    return out


def make_text_fixer(container, story_terms):
    terms = (container.get("glossary_data") or {}).get("terms") or []
    for t in terms:
        if isinstance(t, list) and len(t) > 1 and t[1] in story_terms:
            t[0] = story_terms[t[1]]
    patches = [p for p in (container.get("patch") or []) if isinstance(p, dict) and p.get("zh")]

    def fix(text):
        for i, t in enumerate(terms):
            val = t[0] if isinstance(t, list) and t else None
            if isinstance(val, list):
                val = val[0] if val else None
            val = val if val else f"※{i}⛬"
            text = text.replace(f"※{i}⛬", val).replace(f"※{i}〓", val)
        for p in patches:
            text = text.replace(p["zh"], " " + str(p.get("en", "")))
        return text

    return fix


def parse_next_data(html):
    m = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', html, re.S)
    return json.loads(m.group(1)) if m else {}


def dig(obj, *path):
    for p in path:
        if isinstance(obj, dict):
            obj = obj.get(p)
        else:
            return None
    return obj


# ---------------------------------------------------------------- client
class WtrClient:
    def __init__(self):
        self.cookie = COOKIE
        self.ua = UA
        self.http = None
        self.curl = False
        self._open()

    def _headers(self):
        h = {"Accept-Language": "en-US,en;q=0.9"}
        if not self.curl:
            h["User-Agent"] = self.ua
        return h

    def _apply_cookies(self):
        for part in (self.cookie or "").split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                try:
                    self.http.cookies.set(k, v, domain="wtr-lab.com")
                except Exception:  # noqa
                    pass

    def _open(self):
        self.curl = bool(CurlSession and USE_CURL)
        if self.curl:
            self.http = CurlSession(impersonate=IMPERSONATE, headers=self._headers(),
                                    timeout=45, allow_redirects=True,
                                    proxies={"http": PROXY, "https": PROXY} if PROXY else None)
        else:
            self.http = httpx.AsyncClient(headers=self._headers(), timeout=45,
                                          follow_redirects=True, proxy=PROXY,
                                          limits=httpx.Limits(max_connections=10))
        self._apply_cookies()
        log.info("HTTP backend: %s", "curl_cffi" if self.curl else "httpx")

    async def close(self):
        if self.http is None:
            return
        if self.curl:
            await self.http.close()
        else:
            await self.http.aclose()

    async def reopen(self, cookie=None, ua=None):
        if cookie is not None:
            self.cookie = cookie
        if ua is not None:
            self.ua = ua
        await self.close()
        self._open()

    async def _request(self, method, url, retries=4, **kw):
        if self.curl and "content" in kw:
            kw["data"] = kw.pop("content")
        last = None
        for attempt in range(retries):
            try:
                r = await self.http.request(method, url, **kw)
                if r.status_code in (429, 500, 502, 503, 504):
                    wait = int(r.headers.get("Retry-After", 0) or 0) or 5 * 2 ** attempt
                    last = f"HTTP {r.status_code}"
                    if r.status_code == 429 and attempt == retries - 1:
                        raise Blocked("HTTP 429")
                    await asyncio.sleep(min(wait, 60))
                    continue
                return r
            except Blocked:
                raise
            except Exception as e:  # transport/timeouts
                last = repr(e)
                await asyncio.sleep(3 * (attempt + 1))
        raise RuntimeError(f"request failed: {url} ({last})")

    async def load_novel(self, lang, nid, slug):
        page = await self._request("GET", f"{BASE}/{lang}/novel/{nid}/{slug}")
        if page.status_code in (403, 503) or "Just a moment" in page.text[:3000]:
            raise Blocked("novel page blocked (Cloudflare)")
        nd = parse_next_data(page.text)
        sdata = dig(nd, "props", "pageProps", "serie", "serie_data", "data") or {}
        title = (sdata.get("title") or dig(nd, "props", "pageProps", "serie", "serie_data", "title")
                 or slug.replace("-", " ").title())
        author = sdata.get("author") or dig(nd, "props", "pageProps", "serie",
                                            "serie_data", "raw_author") or "Unknown"
        r = await self._request("GET", f"{BASE}/api/chapters/{nid}")
        if r.status_code in (403, 503):
            raise Blocked("chapter list blocked (Cloudflare)")
        try:
            chapters = r.json().get("chapters") or []
        except ValueError:
            raise Blocked("chapter list is not JSON (blocked?)")
        if not chapters:
            raise RuntimeError("No chapters found for this novel.")
        chapters.sort(key=lambda c: c.get("order", 0))
        try:
            tr = await self._request("GET", f"{BASE}/api/v2/reader/terms/{nid}.json")
            terms = story_terms_from(tr.json()) if tr.status_code == 200 else {}
        except Exception:  # noqa
            terms = {}
        return {"lang": lang, "nid": nid, "slug": slug, "title": str(title),
                "author": str(author), "cover": sdata.get("image"),
                "chapters": {int(c["order"]): c for c in chapters}, "terms": terms}

    async def fetch_chapter(self, novel, order):
        c = novel["chapters"][order]
        payload = {"translate": "ai", "language": novel["lang"], "raw_id": str(novel["nid"]),
                   "chapter_no": str(order), "retry": False, "force_retry": False}
        if c.get("id") is not None:
            payload["chapter_id"] = c["id"]
        headers = {"Content-Type": "application/json;charset=UTF-8", "Origin": BASE,
                   "Referer": f"{BASE}/{novel['lang']}/novel/{novel['nid']}/"
                              f"{novel['slug']}/chapter-{order}"}
        r = await self._request("POST", f"{BASE}/api/reader/get",
                                content=json.dumps(payload), headers=headers)
        if r.status_code in (403, 503):
            raise Blocked("HTTP %d" % r.status_code)
        try:
            j = r.json()
        except ValueError:
            raise EmptyChapter("non-JSON response")
        if j.get("code") == "CHAPTER_LOCKED":
            raise ChapterLocked()
        if (j.get("requireTurnstile") or str(j.get("code")) == "1401"
                or "turnstile" in json.dumps(j)[:400].lower()):
            raise Blocked("turnstile")
        container = find_body_container(j)
        if container is None and j.get("content_url"):
            url = j["content_url"]
            if url.startswith("//"):
                url = "https:" + url
            elif url.startswith("/"):
                url = BASE + url
            cr = await self._request("GET", url)
            if cr.status_code in (403, 429):
                raise Blocked("content HTTP %d" % cr.status_code)
            container = find_body_container(parse_content_response(cr.text, j))
        if container is None:
            raise EmptyChapter("empty body")
        body = container["body"]
        if isinstance(body, str):
            try:
                body = decrypt_text(body)
            except Exception as e:
                raise BadKey(repr(e)) from e
        fix = make_text_fixer(container, novel["terms"])
        title = fix(str(container.get("title") or c.get("title") or f"Chapter {order}"))
        images = container.get("images") or []
        blocks, img_i = [], 0
        for el in body:
            if el == "[image]":
                url = images[img_i] if img_i < len(images) else ""
                img_i += 1
                if url:
                    blocks.append(("img", url))
            else:
                blocks.append(("p", fix(str(el))))
        return title, blocks

    async def fetch_chapter_retry(self, novel, order):
        for i in range(len(RETRY_DELAYS) + 1):
            try:
                return await self.fetch_chapter(novel, order)
            except EmptyChapter:
                if i >= len(RETRY_DELAYS):
                    raise
                await asyncio.sleep(RETRY_DELAYS[i])

    async def get_bytes(self, url):
        if url.startswith("//"):
            url = "https:" + url
        r = await self._request("GET", url, retries=2)
        if r.status_code != 200 or len(r.content) > 8 * 1024 * 1024:
            return None, None
        ct = r.headers.get("content-type", "").split(";")[0].strip()
        return r.content, norm_mime(ct, url)


# ------------------------------------------------------------------ EPUB
IMG_EXT = {"image/jpeg": "jpg", "image/png": "png", "image/gif": "gif", "image/webp": "webp"}


def norm_mime(ct, url=""):
    ct = (ct or "").lower()
    if ct == "image/jpg":
        return "image/jpeg"
    if ct in IMG_EXT:
        return ct
    ext = url.split("?")[0].rsplit(".", 1)[-1].lower()
    return {"png": "image/png", "gif": "image/gif", "webp": "image/webp"}.get(ext, "image/jpeg")


def build_epub(meta, chapters, cover=None):
    """chapters: list of (num, title, blocks); blocks: ('p',text)|('img',(name,bytes,mime))."""
    book_id = f"urn:uuid:{uuid.uuid4()}"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    manifest, spine, nav_items, files = [], [], [], {}

    for num, title, blocks in chapters:
        fid = f"ch{num}"
        body = [f"<h1>{esc(title)}</h1>"]
        for kind, val in blocks:
            if kind == "p":
                body.append(f"<p>{esc(val)}</p>")
            else:
                name, data, mime = val
                files[f"OEBPS/images/{name}"] = data
                manifest.append(f'<item id="im_{name}" href="images/{name}" media-type="{mime}"/>')
                body.append(f'<p><img src="images/{name}" alt=""/></p>')
        files[f"OEBPS/{fid}.xhtml"] = (
            '<?xml version="1.0" encoding="utf-8"?>\n<!DOCTYPE html>\n'
            '<html xmlns="http://www.w3.org/1999/xhtml"><head><meta charset="utf-8"/>'
            f"<title>{esc(title)}</title></head><body>{''.join(body)}</body></html>").encode()
        manifest.append(f'<item id="{fid}" href="{fid}.xhtml" media-type="application/xhtml+xml"/>')
        spine.append(f'<itemref idref="{fid}"/>')
        nav_items.append((fid, title))

    cover_meta = ""
    if cover:
        cdata, cmime = cover
        ext = IMG_EXT.get(cmime, "jpg")
        files[f"OEBPS/cover.{ext}"] = cdata
        manifest.append(f'<item id="cover-img" href="cover.{ext}" media-type="{cmime}" '
                        'properties="cover-image"/>')
        cover_meta = '<meta name="cover" content="cover-img"/>'

    nav = ('<?xml version="1.0" encoding="utf-8"?>\n<!DOCTYPE html>\n'
           '<html xmlns="http://www.w3.org/1999/xhtml" xmlns:epub="http://www.idpf.org/2007/ops">'
           '<head><meta charset="utf-8"/><title>Contents</title></head><body>'
           '<nav epub:type="toc"><h1>Contents</h1><ol>'
           + "".join(f'<li><a href="{f}.xhtml">{esc(t)}</a></li>' for f, t in nav_items)
           + "</ol></nav></body></html>")
    ncx = ('<?xml version="1.0" encoding="utf-8"?>\n'
           '<ncx xmlns="http://www.daisy.org/z3986/2005/ncx/" version="2005-1">'
           f'<head><meta name="dtb:uid" content="{book_id}"/></head>'
           f'<docTitle><text>{esc(meta["title"])}</text></docTitle><navMap>'
           + "".join(f'<navPoint id="n{i}" playOrder="{i}"><navLabel><text>{esc(t)}</text>'
                     f'</navLabel><content src="{f}.xhtml"/></navPoint>'
                     for i, (f, t) in enumerate(nav_items, 1))
           + "</navMap></ncx>")
    opf = ('<?xml version="1.0" encoding="utf-8"?>\n'
           '<package xmlns="http://www.idpf.org/2007/opf" version="3.0" unique-identifier="bid">'
           '<metadata xmlns:dc="http://purl.org/dc/elements/1.1/">'
           f'<dc:identifier id="bid">{book_id}</dc:identifier>'
           f'<dc:title>{esc(meta["title"])}</dc:title>'
           f'<dc:creator>{esc(meta["author"])}</dc:creator>'
           '<dc:language>en</dc:language>'
           f'<meta property="dcterms:modified">{now}</meta>{cover_meta}</metadata><manifest>'
           '<item id="nav" href="nav.xhtml" media-type="application/xhtml+xml" properties="nav"/>'
           '<item id="ncx" href="toc.ncx" media-type="application/x-dtbncx+xml"/>'
           + "".join(manifest) + '</manifest><spine toc="ncx"><itemref idref="nav"/>'
           + "".join(spine) + "</spine></package>")
    container = ('<?xml version="1.0"?><container version="1.0" '
                 'xmlns="urn:oasis:names:tc:opendocument:xmlns:container"><rootfiles>'
                 '<rootfile full-path="OEBPS/content.opf" '
                 'media-type="application/oebps-package+xml"/></rootfiles></container>')

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(zipfile.ZipInfo("mimetype"), "application/epub+zip",
                   compress_type=zipfile.ZIP_STORED)
        z.writestr("META-INF/container.xml", container, compress_type=zipfile.ZIP_DEFLATED)
        z.writestr("OEBPS/content.opf", opf, compress_type=zipfile.ZIP_DEFLATED)
        z.writestr("OEBPS/nav.xhtml", nav, compress_type=zipfile.ZIP_DEFLATED)
        z.writestr("OEBPS/toc.ncx", ncx, compress_type=zipfile.ZIP_DEFLATED)
        for path, data in files.items():
            z.writestr(path, data, compress_type=zipfile.ZIP_DEFLATED)
    return buf.getvalue()


def build_parts(meta, chapters, cover, limit=TG_FILE_LIMIT):
    """Build EPUB; if too large split chapters in half recursively."""
    epub = build_epub(meta, chapters, cover)
    if len(epub) <= limit or len(chapters) < 2:
        return [(chapters, epub)]
    del epub
    mid = len(chapters) // 2
    return build_parts(meta, chapters[:mid], cover, limit) + \
        build_parts(meta, chapters[mid:], cover, limit)


# ------------------------------------------------------------ bot logic
client: "WtrClient | None" = None
JOB_SEM = asyncio.Semaphore(MAX_JOBS)
JOBS = {}      # chat_id -> {"cancel": bool, "st": dict}
CACHE = {}     # (nid, order) -> (title, blocks)
_bg = []


def cache_put(key, val):
    if len(CACHE) >= CACHE_MAX:
        for k in list(CACHE)[:200]:
            CACHE.pop(k, None)
    CACHE[key] = val


def clean_title(s):
    """'Beast Tamer: I'm Really Not a Villain' -> 'Beast Tamer Im Really Not a Villain'"""
    s = str(s).replace("'", "").replace("’", "")
    s = re.sub(r"[^\w\- ]+", " ", s, flags=re.U)
    return re.sub(r"\s+", " ", s).strip()[:80] or "novel"


def epub_filename(novel, a, b):
    w = max(2, len(str(max(novel["chapters"]))))
    return f"[ {a:0{w}d}-{b:0{w}d} ] {clean_title(novel['title'])}.epub"


def bar(done, total, n=12):
    f = int(n * done / total) if total else 0
    return "█" * f + "░" * (n - f)


async def safe_edit(msg, text, markup=None):
    try:
        await msg.edit_text(text, reply_markup=markup)
    except BadRequest as e:
        if "not modified" not in str(e).lower():
            log.debug("edit failed: %s", e)
    except Exception as e:  # noqa
        log.debug("edit failed: %s", e)


class Throttle:
    def __init__(self):
        self.until = 0.0
        self.delay = REQUEST_DELAY

    async def gate(self):
        while True:
            w = self.until - time.time()
            if w <= 0:
                return
            await asyncio.sleep(min(w, 5))

    def trip(self, secs):
        self.until = max(self.until, time.time() + secs)
        self.delay = min(self.delay * 1.5, 20)

    def ok(self):
        self.delay = max(REQUEST_DELAY, self.delay * 0.97)

    def pause(self):
        return self.delay * random.uniform(0.7, 1.4)


async def run_job(app, chat_id, msg, novel, first, last, chunk=0, base=None):
    """chunk=0 -> one EPUB for the range. chunk=N -> one EPUB per N chapters
    (buckets aligned to `base`). Each EPUB is built and SENT as soon as its
    bucket has been downloaded."""
    job = JOBS[chat_id]
    nid = novel["nid"]
    base = first if base is None else base
    orders = [o for o in sorted(novel["chapters"]) if first <= o <= last]
    capped = len(orders) > MAX_CHAPTERS
    orders = orders[:MAX_CHAPTERS]
    if not orders:
        await safe_edit(msg, "❌ No chapters in that range.")
        JOBS.pop(chat_id, None)
        return
    total = len(orders)
    results, failed = {}, {}
    st = {"done": 0, "halt": False, "badkey": False, "blocks": 0, "note": "", "ui": 0.0}
    job["st"] = st
    th = Throttle()
    cancel_kb = InlineKeyboardMarkup([[InlineKeyboardButton("✖ Cancel", callback_data="cancel")]])
    buckets = {}
    for o in orders:
        buckets.setdefault((o - base) // chunk if chunk else 0, []).append(o)
    cover_box = {"done": False, "val": None}
    sent = 0
    nb = len(buckets)

    async def progress(force=False):
        now = time.time()
        if force or now - st["ui"] > 4:
            st["ui"] = now
            txt = (f"📥 {novel['title']}\n{bar(st['done'], total)} {st['done']}/{total}\n"
                   f"✅ {len(results)}  ⚠️ {len(failed)}  📤 {sent} EPUB sent")
            if st["note"]:
                txt += "\n" + st["note"]
            await safe_edit(msg, txt, cancel_kb)

    async def get_chapter(order):
        strikes = 0
        while True:
            if job["cancel"]:
                return None
            await th.gate()
            st["note"] = ""
            try:
                return await client.fetch_chapter_retry(novel, order)
            except Blocked:
                if strikes >= len(BLOCK_COOLDOWNS):
                    raise
                cd = BLOCK_COOLDOWNS[strikes]
                strikes += 1
                st["blocks"] += 1
                th.trip(cd)
                st["note"] = f"⏸ Rate-limited by wtr-lab. Waiting {cd}s then retrying {order}…"
                await progress(True)

    async def worker(q):
        while not (job["cancel"] or st["halt"] or st["badkey"]):
            try:
                order = q.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                hit = CACHE.get((nid, order))
                if hit is None:
                    got = await get_chapter(order)
                    if got is None:
                        return
                    title, blocks = got
                    if not re.match(rf"^\s*(chapter\s*)?{order}\b", title, re.I):
                        title = f"{order}: {title}"
                    hit = (title, blocks)
                    cache_put((nid, order), hit)
                    th.ok()
                    await asyncio.sleep(th.pause())
                results[order] = hit
            except ChapterLocked:
                failed[order] = "not AI translated"
            except Blocked:
                failed[order] = "blocked"
                st["halt"] = True
            except BadKey:
                st["badkey"] = True
                return
            except Exception as e:  # noqa
                log.warning("chapter %s failed: %r", order, e)
                failed[order] = "empty/failed"
            st["done"] += 1
            await progress()

    async def tg_send(chs, epub, cap):
        a, b = chs[0][0], chs[-1][0]
        for _ in range(5):
            try:
                await app.bot.send_document(
                    chat_id, document=io.BytesIO(epub), filename=epub_filename(novel, a, b),
                    caption=cap[:1000], read_timeout=300, write_timeout=300)
                return True
            except RetryAfter as e:
                await asyncio.sleep(int(getattr(e, "retry_after", 5)) + 1)
        return False

    async def send_bucket(bo):
        nonlocal sent
        have = [o for o in bo if o in results]
        if not have:
            return
        img_bytes, final = 0, []
        for o in have:
            title, blocks = results[o]
            out = []
            for k, (kind, val) in enumerate(blocks):
                if kind == "p":
                    out.append(("p", val))
                elif img_bytes < MAX_IMG_BYTES:
                    try:
                        data, mime = await client.get_bytes(val)
                    except Exception:  # noqa
                        data = None
                    if data:
                        img_bytes += len(data)
                        out.append(("img", (f"i{o}_{k}.{IMG_EXT[mime]}", data, mime)))
            final.append((o, title, out))
        if not cover_box["done"]:
            cover_box["done"] = True
            if novel.get("cover"):
                try:
                    cdata, cmime = await client.get_bytes(novel["cover"])
                    if cdata:
                        cover_box["val"] = (cdata, cmime)
                except Exception:  # noqa
                    pass
        st["note"] = "📦 Building EPUB…"
        await progress(True)
        parts = await asyncio.to_thread(build_parts, novel, final, cover_box["val"])
        locked = [o for o in bo if failed.get(o) == "not AI translated"]
        missing = [o for o in bo if o not in results and o not in locked]
        for i, (chs, epub) in enumerate(parts, 1):
            if len(epub) > TG_FILE_LIMIT:
                await app.bot.send_message(chat_id, f"⚠️ Chapter {chs[0][0]} alone exceeds 50 MB, skipped.")
                continue
            cap = f"📚 {novel['title']}\nChapters {chs[0][0]}-{chs[-1][0]} ({len(chs)} ok)"
            if len(parts) > 1:
                cap += f"\n📎 Part {i}/{len(parts)}"
            if i == 1:
                if locked:
                    cap += f"\n🔒 Not AI-translated: {', '.join(map(str, locked[:15]))}"
                if missing:
                    cap += f"\n⚠️ Missing {len(missing)} (first: {missing[0]})"
            if await tg_send(chs, epub, cap):
                sent += 1
            await asyncio.sleep(1)
        st["note"] = ""

    try:
        if JOB_SEM.locked():
            await safe_edit(msg, "⏳ Queued - another job is running…", cancel_kb)
        async with JOB_SEM:
            await progress(True)
            for key in sorted(buckets):
                if job["cancel"] or st["halt"] or st["badkey"]:
                    break
                bo = buckets[key]
                q = asyncio.Queue()
                for o in bo:
                    q.put_nowait(o)
                await asyncio.gather(*(worker(q) for _ in range(WORKERS)))
                if job["cancel"] or st["badkey"]:
                    break
                await send_bucket(bo)   # sent right away, even if partial/halted
                await progress(True)

        if job["cancel"]:
            await safe_edit(msg, f"❌ Cancelled. {sent} EPUB already sent.")
            return
        if st["badkey"]:
            await safe_edit(msg, "🔑 Decryption failed - wtr-lab probably changed its AES key. "
                                 "Set WTR_AES_KEY (see WebToEpub WtrlabParser.AES_KEY).")
            return
        if sent == 0:
            why = ("🚫 wtr-lab keeps asking for a captcha from this server IP.\n"
                   "Try later with a smaller range, or log in and send /cookie "
                   "(anonymous quota is ~10 chapters)." if st["halt"] else
                   "❌ No chapter could be downloaded.\n"
                   + "\n".join(f"{o}: {w}" for o, w in sorted(failed.items())[:8]))
            await safe_edit(msg, why)
            return

        retry_nums = sorted(o for o in orders if o not in results
                            and failed.get(o) != "not AI translated")
        if retry_nums:
            rd = (f"ar:{chunk}:{base}:{retry_nums[0]}-{last}" if chunk
                  else f"r:{retry_nums[0]}-{last}")
            kb = InlineKeyboardMarkup([[InlineKeyboardButton(
                f"▶ Resume {retry_nums[0]}-{last}", callback_data=rd)]])
            extra = "\n🚫 wtr-lab limit hit - use /cookie for more." if st["halt"] else ""
            extra += f"\n✂️ Limited to {MAX_CHAPTERS} chapters per run." if capped else ""
            await safe_edit(msg, f"⏸ Partial: {len(results)}/{total} chapters, {sent} EPUB sent."
                                 f"{extra}\nWait a few minutes, then tap Resume "
                                 "(done chapters are cached).", kb)
        else:
            await safe_edit(msg, f"✅ Done! {sent} EPUB sent.")
    except Exception as e:  # noqa
        log.exception("job failed")
        await safe_edit(msg, f"❌ Error: {e}")
    finally:
        JOBS.pop(chat_id, None)


# ------------------------------------------------------------- handlers
async def save_cookie_pinned(bot, chat_id, val):
    try:
        m = await bot.send_message(chat_id, COOKIE_TAG + val)
        await bot.pin_chat_message(chat_id, m.message_id, disable_notification=True)
    except Exception as e:  # noqa
        log.warning("could not pin cookie: %r", e)


async def load_cookie_pinned(bot):
    for uid in ADMIN_IDS:
        try:
            pm = (await bot.get_chat(uid)).pinned_message
            if pm and pm.text and pm.text.startswith(COOKIE_TAG):
                return pm.text[len(COOKIE_TAG):].strip() or None
        except Exception as e:  # noqa
            log.info("no pinned cookie for %s: %r", uid, e)
    return None


def is_admin(update):
    return bool(update.effective_user) and update.effective_user.id in ADMIN_IDS


async def start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "📚 wtr-lab → EPUB bot\n\nSend a novel link like:\n"
        "https://wtr-lab.com/en/novel/12345/novel-slug\n\n"
        "Then pick a range, ✏️ Custom (e.g. 20-30) or ⚡ Auto EPUB "
        "(25/50/100 chapters per file).\n"
        "Only AI-translated chapters are available.\n\n"
        "/status – job progress   /cancel – stop job")


async def status_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    j = JOBS.get(update.effective_chat.id)
    if not j:
        await update.message.reply_text("No job running.")
        return
    st = j.get("st") or {}
    await update.message.reply_text(f"Running: {st.get('done', 0)} chapters processed, "
                                    f"{st.get('blocks', 0)} rate-limit hits. {st.get('note', '')}")


async def cancel_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.chat_data.pop("await", None)
    j = JOBS.get(update.effective_chat.id)
    if j:
        j["cancel"] = True
        await update.message.reply_text("Cancelling…")
    else:
        await update.message.reply_text("No job running.")


async def cookie_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update):
        await update.message.reply_text("Admin only.")
        return
    val = " ".join(ctx.args).strip()
    if not val:
        await update.message.reply_text(
            "Usage: /cookie name=value; name2=value2\n(or /cookie clear)\n"
            "Login to wtr-lab in your browser, copy ALL cookies of wtr-lab.com "
            "(Cookie-Editor → Export → header string).")
        return
    if val.lower() == "clear":
        val = ""
    await client.reopen(cookie=val)
    try:
        with open(COOKIE_FILE, "w", encoding="utf-8") as f:
            f.write(val)
    except OSError:
        pass
    try:
        await update.message.delete()
    except Exception:  # noqa
        pass
    await save_cookie_pinned(ctx.bot, update.effective_chat.id, val)
    await ctx.bot.send_message(update.effective_chat.id, "🍪 Cookie updated and saved (pinned message).")


async def ua_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update):
        await update.message.reply_text("Admin only.")
        return
    val = " ".join(ctx.args).strip()
    if not val:
        await update.message.reply_text("Usage: /ua <user agent string>")
        return
    await client.reopen(ua=val)
    await update.message.reply_text("User-Agent updated (used only without curl_cffi).")


def range_keyboard(first, last):
    seen, row = set(), []
    for a, b in [(1, 20), (21, 100), (1, 100), (101, 200)]:
        a2, b2 = max(a, first), min(b, last)
        if a2 <= b2 and (a2, b2) not in seen and (a2, b2) != (first, last):
            seen.add((a2, b2))
            row.append(InlineKeyboardButton(f"{a2}-{b2}", callback_data=f"r:{a2}-{b2}"))
    row.append(InlineKeyboardButton(f"All ({first}-{last})", callback_data=f"r:{first}-{last}"))
    rows = [row[i:i + 2] for i in range(0, len(row), 2)]
    rows.append([InlineKeyboardButton("✏️ Custom", callback_data="custom")])
    rows.append([InlineKeyboardButton("⚡ Auto EPUB", callback_data="auto")])
    return InlineKeyboardMarkup(rows)


AUTO_KB = InlineKeyboardMarkup([
    [InlineKeyboardButton("25", callback_data="c:25"),
     InlineKeyboardButton("50", callback_data="c:50"),
     InlineKeyboardButton("100", callback_data="c:100")],
    [InlineKeyboardButton("✏️ Custom", callback_data="cx")],
])


async def on_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    text = update.message.text or ""
    chat_id = update.effective_chat.id
    m = URL_RE.search(text)
    if m:
        ctx.chat_data.pop("await", None)
        if chat_id in JOBS:
            await update.message.reply_text("⏳ A job is already running. /cancel it first.")
            return
        status = await update.message.reply_text("🔎 Reading novel…")
        try:
            novel = await client.load_novel(m.group(1).lower(), m.group(2), m.group(3))
        except Blocked:
            await safe_edit(status, "🚫 wtr-lab blocked the request (Cloudflare). "
                                    "Try again later or use /cookie.")
            return
        except Exception as e:  # noqa
            await safe_edit(status, f"❌ Could not read novel: {e}")
            return
        ctx.chat_data["novel"] = novel
        orders = sorted(novel["chapters"])
        await safe_edit(status,
                        f"📖 {novel['title']}\n✍️ {novel['author']}\n"
                        f"📑 {len(orders)} chapters ({orders[0]}–{orders[-1]})\n\n"
                        "Pick a range, ✏️ Custom or ⚡ Auto EPUB:",
                        range_keyboard(orders[0], orders[-1]))
        return
    novel = ctx.chat_data.get("novel")
    if not novel:
        await update.message.reply_text("Send a wtr-lab novel link first 🙂")
        return
    orders = sorted(novel["chapters"])
    mode = ctx.chat_data.get("await")
    t = text.strip()
    if mode == "chunk":
        if t.isdigit() and int(t) > 0:
            ctx.chat_data.pop("await", None)
            await launch(ctx, chat_id, novel, orders[0], orders[-1], chunk=int(t))
        else:
            await update.message.reply_text("Send a number, e.g. 20 (chapters per EPUB).")
        return
    rm = RANGE_RE.match(text)
    if rm or t.lower() == "all":
        ctx.chat_data.pop("await", None)
        a, b = (int(rm.group(1)), int(rm.group(2))) if rm else (orders[0], orders[-1])
        await launch(ctx, chat_id, novel, a, b)
        return
    if mode == "range":
        await update.message.reply_text("Send like 20-30 (from-to).")
        return
    await update.message.reply_text("Send a range like 20-30, or use the buttons.")


async def launch(ctx, chat_id, novel, a, b, chunk=0, base=None):
    if a > b:
        a, b = b, a
    orders = sorted(novel["chapters"])
    a, b = max(a, orders[0]), min(b, orders[-1])
    if chat_id in JOBS:
        await ctx.bot.send_message(chat_id, "⏳ A job is already running.")
        return
    JOBS[chat_id] = {"cancel": False, "st": {}}
    label = f"{a}-{b}" + (f" ({chunk} ch/EPUB)" if chunk else "")
    msg = await ctx.bot.send_message(chat_id, f"⏳ Starting {label}…")
    t = asyncio.create_task(run_job(ctx.application, chat_id, msg, novel, a, b, chunk, base))
    _bg.append(t)
    t.add_done_callback(lambda x: _bg.remove(x) if x in _bg else None)


async def on_button(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    chat_id = q.message.chat_id
    d = q.data or ""
    if d == "cancel":
        if chat_id in JOBS:
            JOBS[chat_id]["cancel"] = True
        return
    novel = ctx.chat_data.get("novel")
    if not novel:
        await q.message.reply_text("Session expired (server restarted). Send the link again.")
        return
    orders = sorted(novel["chapters"])
    if d == "custom":
        ctx.chat_data["await"] = "range"
        await q.message.reply_text(f"✏️ Type the range, e.g. 20-30  (available {orders[0]}-{orders[-1]})")
    elif d == "auto":
        await q.message.reply_text("⚡ Auto EPUB: how many chapters per EPUB?", reply_markup=AUTO_KB)
    elif d == "cx":
        ctx.chat_data["await"] = "chunk"
        await q.message.reply_text("✏️ Type chapters per EPUB, e.g. 20")
    elif d.startswith("c:"):
        await launch(ctx, chat_id, novel, orders[0], orders[-1], chunk=int(d[2:]))
    elif d.startswith("ar:"):
        _, chunk, base, rng = d.split(":", 3)
        a, b = (int(x) for x in rng.split("-"))
        await launch(ctx, chat_id, novel, a, b, chunk=int(chunk), base=int(base))
    elif d.startswith("r:"):
        a, b = (int(x) for x in d[2:].split("-"))
        await launch(ctx, chat_id, novel, a, b)


async def on_error(update, ctx: ContextTypes.DEFAULT_TYPE):
    log.error("handler error: %r", ctx.error)


async def keepalive():
    url = os.environ.get("KEEPALIVE_URL") or os.environ.get("RENDER_EXTERNAL_URL")
    if not url:
        return
    async with httpx.AsyncClient(timeout=20) as c:
        while True:
            await asyncio.sleep(540)
            try:
                await c.get(url)
            except Exception:  # noqa
                pass


async def post_init(app):
    global client
    client = WtrClient()
    c = await load_cookie_pinned(app.bot)
    if c:
        await client.reopen(cookie=c)
        log.info("cookie restored from pinned message")
    _bg.append(asyncio.create_task(keepalive()))


async def post_shutdown(app):
    if client:
        await client.close()


# ----------------------------------------------- health server (Render)
class Health(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    do_HEAD = do_GET

    def log_message(self, *a):
        pass


def serve_health():
    ThreadingHTTPServer(("0.0.0.0", PORT), Health).serve_forever()


def main():
    if not BOT_TOKEN:
        raise SystemExit("Set BOT_TOKEN environment variable.")
    threading.Thread(target=serve_health, daemon=True).start()
    app = (Application.builder().token(BOT_TOKEN).concurrent_updates(True)
           .post_init(post_init).post_shutdown(post_shutdown).build())
    app.add_handler(CommandHandler(["start", "help"], start))
    app.add_handler(CommandHandler("status", status_cmd))
    app.add_handler(CommandHandler("cancel", cancel_cmd))
    app.add_handler(CommandHandler("cookie", cookie_cmd))
    app.add_handler(CommandHandler("ua", ua_cmd))
    app.add_handler(CallbackQueryHandler(on_button))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))
    app.add_error_handler(on_error)
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
