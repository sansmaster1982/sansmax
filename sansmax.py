import getpass
import re
import socket
import ssl
import time
import uuid
from pathlib import Path
from typing import Any
import json
import datetime

import msgpack

# Номер телефона аккаунта в международном формате, например +79001234567.
# Если оставить значение-заглушку PLACEHOLDER_PHONE, при первом входе скрипт
# спросит номер интерактивно. Это нужно для .exe, где исходник не отредактируешь.
PLACEHOLDER_PHONE = "+79001234567"
PHONE = PLACEHOLDER_PHONE

HOST = "api.oneme.ru"
PORT = 443
PROTO_VER = 10
APP_VERSION = "26.11.0"

TOKEN_FILE = Path("max_login_token.txt")

seq = 0


# ============================================================
# Token storage
# ============================================================

def save_token(token: str):
    TOKEN_FILE.write_text(token, encoding="utf-8")
    TOKEN_FILE.chmod(0o600)


def load_token() -> str | None:
    if not TOKEN_FILE.exists():
        return None

    token = TOKEN_FILE.read_text(encoding="utf-8").strip()
    return token or None


def delete_token():
    TOKEN_FILE.unlink(missing_ok=True)


_resolved_phone: str | None = None


def resolve_phone() -> str:
    """
    Возвращает номер телефона для SMS-авторизации.
    Если в коде осталась заглушка PLACEHOLDER_PHONE — спрашивает номер у пользователя.
    Результат кешируется, чтобы не спрашивать дважды за один запуск.
    """
    global _resolved_phone

    if _resolved_phone:
        return _resolved_phone

    configured = PHONE.strip()
    if configured and configured != PLACEHOLDER_PHONE:
        _resolved_phone = configured
        return _resolved_phone

    entered = input("Введите номер телефона аккаунта (например +79001234567): ").strip()
    _resolved_phone = entered or configured
    return _resolved_phone


# ============================================================
# Debug / formatting
# ============================================================

def raw_ascii(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in data)


def mask_secret(value: Any):
    if isinstance(value, str) and len(value) > 80:
        return value[:12] + "...MASKED..." + value[-8:]
    return value


def safe_payload(payload: dict) -> dict:
    result = {}

    for key, value in payload.items():
        k = key.lower()

        if k in {"token", "password", "oldpassword", "newpassword"}:
            result[key] = "***MASKED***"
        elif isinstance(value, dict):
            result[key] = safe_payload(value)
        elif isinstance(value, list):
            result[key] = [
                safe_payload(x) if isinstance(x, dict) else mask_secret(x)
                for x in value
            ]
        else:
            result[key] = mask_secret(value)

    return result


def print_result(name: str, decoded, raw: bytes, max_ascii: int = 3000):
    print(f"\n=== {name} ===")
    if decoded is not None:
        print(decoded)
    else:
        print(raw_ascii(raw)[:max_ascii])
    print("=" * (len(name) + 8))


# ============================================================
# MsgPack / protocol
# ============================================================

def pack_payload(obj: dict) -> bytes:
    return msgpack.packb(obj, use_bin_type=True)


def unpack_payload(data: bytes):
    """
    MAX иногда кладёт 2 служебных байта перед обычным MsgPack.
    Маленькие ответы нормально парсятся с offset=2.
    Большие LOGIN/HISTORY payload могут содержать compact/ref encoding,
    поэтому полностью не парсятся обычным msgpack.
    """
    for offset in (0, 1, 2, 3, 4):
        try:
            return msgpack.unpackb(
                data[offset:],
                raw=False,
                strict_map_key=False,
            )
        except Exception:
            pass

    return None


def send_packet(sock: ssl.SSLSocket, opcode: int, payload: dict):
    global seq

    body = pack_payload(payload)

    header = bytearray(10)
    header[0] = PROTO_VER
    header[1] = 0
    header[2] = (seq >> 8) & 0xFF
    header[3] = seq & 0xFF
    header[4] = (opcode >> 8) & 0xFF
    header[5] = opcode & 0xFF

    length = len(body)
    header[6] = (length >> 24) & 0xFF
    header[7] = (length >> 16) & 0xFF
    header[8] = (length >> 8) & 0xFF
    header[9] = length & 0xFF

    print(">>", {
        "seq": seq,
        "opcode": opcode,
        "payload": safe_payload(payload),
    })

    seq += 1
    sock.sendall(header + body)


def recv_exact(sock: ssl.SSLSocket, n: int) -> bytes:
    chunks = []
    left = n

    while left > 0:
        chunk = sock.recv(left)
        if not chunk:
            raise ConnectionError("socket closed")

        chunks.append(chunk)
        left -= len(chunk)

    return b"".join(chunks)


def recv_packet(sock: ssl.SSLSocket, print_body: bool = True):
    header = recv_exact(sock, 10)

    ver = header[0]
    cmd = header[1]
    resp_seq = (header[2] << 8) | header[3]
    opcode = (header[4] << 8) | header[5]

    length_raw = (
        (header[6] << 24)
        | (header[7] << 16)
        | (header[8] << 8)
        | header[9]
    )

    flags = (length_raw >> 24) & 0xFF
    payload_len = length_raw & 0x00FFFFFF

    body = recv_exact(sock, payload_len) if payload_len else b""
    decoded = unpack_payload(body)

    print("<< header:", {
        "ver": ver,
        "cmd": cmd,
        "seq": resp_seq,
        "opcode": opcode,
        "flags": flags,
        "payload_len": payload_len,
    })

    if print_body:
        if decoded is not None:
            print("<< payload:", decoded)
        else:
            print("<< raw:", body[:500])
            print("<< ascii:", raw_ascii(body)[:1000])

    return cmd, opcode, decoded, body


def connect():
    global seq
    seq = 0

    context = ssl.create_default_context()
    raw = socket.create_connection((HOST, PORT), timeout=30)
    tls = context.wrap_socket(raw, server_hostname=HOST)
    tls.settimeout(30)

    return tls


# ============================================================
# Generic raw readers
# ============================================================

def read_int_after_key(data: bytes, key: bytes) -> int | None:
    pos = data.find(key)
    if pos == -1:
        return None

    p = pos + len(key)
    if p >= len(data):
        return None

    typ = data[p]
    p += 1

    if typ == 0xD2 and p + 4 <= len(data):
        return int.from_bytes(data[p:p + 4], "big", signed=True)

    if typ == 0xD3 and p + 8 <= len(data):
        return int.from_bytes(data[p:p + 8], "big", signed=True)

    if 0x00 <= typ <= 0x7F:
        return typ

    if 0xE0 <= typ <= 0xFF:
        return typ - 256

    return None


def read_str_after_key(data: bytes, key: bytes) -> str | None:
    pos = data.find(key)
    if pos == -1:
        return None

    p = pos + len(key)
    if p >= len(data):
        return None

    typ = data[p]
    p += 1

    if 0xA0 <= typ <= 0xBF:
        n = typ & 0x1F
    elif typ == 0xD9 and p < len(data):
        n = data[p]
        p += 1
    elif typ == 0xDA and p + 2 <= len(data):
        n = int.from_bytes(data[p:p + 2], "big")
        p += 2
    elif typ == 0xDB and p + 4 <= len(data):
        n = int.from_bytes(data[p:p + 4], "big")
        p += 4
    else:
        return None

    return data[p:p + n].decode("utf-8", errors="ignore").strip()


def extract_visible_utf8_strings(data: bytes) -> list[str]:
    strings = []

    for m in re.finditer(rb"[ -~]{4,}", data):
        s = m.group(0).decode("utf-8", errors="ignore").strip()
        if s:
            strings.append(s)

    buf = bytearray()
    for b in data:
        if b >= 0x80 or b in (0x0A, 0x0D, 0x20) or 48 <= b <= 57:
            buf.append(b)
        else:
            if len(buf) >= 6:
                s = bytes(buf).decode("utf-8", errors="ignore").strip()
                if len(s) >= 4:
                    strings.append(s)
            buf.clear()

    if len(buf) >= 6:
        s = bytes(buf).decode("utf-8", errors="ignore").strip()
        if len(s) >= 4:
            strings.append(s)

    out = []
    seen = set()

    for s in strings:
        s = re.sub(r"\s+", " ", s).strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)

    return out


def find_long_token(data: bytes) -> str | None:
    valid = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-+.~=")
    best = None
    cur = []

    for b in data:
        c = chr(b)

        if c in valid:
            cur.append(c)
        else:
            if len(cur) > 100:
                token = "".join(cur)
                if best is None or len(token) > len(best):
                    best = token
            cur = []

    if len(cur) > 100:
        token = "".join(cur)
        if best is None or len(token) > len(best):
            best = token

    return best


def find_uuid_in_raw(data: bytes) -> str | None:
    m = re.search(
        rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        data,
    )
    return m.group(0).decode("utf-8") if m else None


# ============================================================
# Auth / login
# ============================================================

def init_session(sock: ssl.SSLSocket):
    send_packet(sock, 6, {
        "userAgent": {
            "deviceType": "ANDROID",
            "locale": "ru",
            "appVersion": APP_VERSION,
        },
        "deviceId": str(uuid.uuid4()),
    })

    cmd, opcode, decoded, raw = recv_packet(sock)
    if cmd != 1:
        raise RuntimeError("INIT failed")


def auth_by_sms(sock: ssl.SSLSocket, phone: str) -> str:
    send_packet(sock, 17, {
        "phone": phone,
        "type": "START_AUTH",
    })

    cmd, opcode, decoded, raw = recv_packet(sock)
    if cmd != 1:
        raise RuntimeError(f"AUTH_REQUEST failed: {decoded or raw_ascii(raw)}")

    verify_token = find_long_token(raw)
    if not verify_token:
        raise RuntimeError("verify token не найден")

    print("VERIFY TOKEN:", mask_secret(verify_token))

    code = input("Введите SMS-код: ").strip()

    send_packet(sock, 18, {
        "token": verify_token,
        "verifyCode": code,
        "authTokenType": "CHECK_CODE",
    })

    cmd, opcode, decoded, raw = recv_packet(sock)
    if cmd != 1:
        raise RuntimeError(f"AUTH_CONFIRM failed: {decoded or raw_ascii(raw)}")

    auth_token = find_long_token(raw)

    if not auth_token and b"passwordChallenge" in raw:
        track_id = find_uuid_in_raw(raw)
        if not track_id:
            raise RuntimeError("passwordChallenge есть, но trackId не найден")

        print("Нужен 2FA-пароль.")
        password = getpass.getpass("Введите 2FA-пароль: ")

        send_packet(sock, 115, {
            "trackId": track_id,
            "password": password,
        })

        cmd, opcode, decoded, raw = recv_packet(sock)
        if cmd != 1:
            raise RuntimeError(f"2FA failed: {decoded or raw_ascii(raw)}")

        auth_token = find_long_token(raw)

    if not auth_token:
        raise RuntimeError("auth token не найден")

    save_token(auth_token)
    print("AUTH TOKEN saved")

    return auth_token


def login(sock: ssl.SSLSocket, token: str):
    send_packet(sock, 19, {
        "token": token,
        "interactive": False,
        "chatsCount": 40,
        "chatsSync": 0,
        "contactsSync": 0,
        "presenceSync": 0,
        "draftsSync": 0,
    })

    cmd, opcode, decoded, raw = recv_packet(sock, print_body=False)
    if cmd != 1:
        raise RuntimeError(f"LOGIN failed: {decoded or raw_ascii(raw)}")

    return decoded, raw


def ensure_logged_in(sock: ssl.SSLSocket) -> tuple[str, object, bytes]:
    token = load_token()

    if token:
        print("Using saved token")
    else:
        token = auth_by_sms(sock, resolve_phone())

    try:
        decoded, raw = login(sock, token)
        return token, decoded, raw
    except Exception as e:
        print("Saved token не сработал:", e)
        print("Прохожу SMS заново")

        delete_token()
        token = auth_by_sms(sock, resolve_phone())
        decoded, raw = login(sock, token)

        return token, decoded, raw


def run_authenticated_call(opcode: int, payload: dict):
    """
    Для экспериментальных security-запросов: новое соединение на каждый вызов.
    Это важно, потому что после cmd=3 сервер иногда закрывает socket.
    """
    token = load_token()
    if not token:
        raise RuntimeError("Нет сохранённого токена")

    with connect() as sock:
        init_session(sock)
        login(sock, token)

        send_packet(sock, opcode, payload)
        return recv_packet(sock)


# ============================================================
# Chat extraction / pretty printers
# ============================================================

def extract_chat_ids_from_login_raw(data: bytes) -> list[int]:
    ids = []

    for m in re.finditer(rb"\xa2id([\xd2\xd3])(.{4,8}).{0,120}?(DIALOG|CHAT|CHANNEL)", data, re.DOTALL):
        typ = m.group(1)
        raw_num = m.group(2)

        try:
            if typ == b"\xd2":
                chat_id = int.from_bytes(raw_num[:4], "big", signed=True)
            else:
                chat_id = int.from_bytes(raw_num[:8], "big", signed=True)

            ids.append(chat_id)
        except Exception:
            pass

    for m in re.finditer(rb"\xa6chatId([\xd2\xd3])(.{4,8})", data, re.DOTALL):
        typ = m.group(1)
        raw_num = m.group(2)

        try:
            if typ == b"\xd2":
                chat_id = int.from_bytes(raw_num[:4], "big", signed=True)
            else:
                chat_id = int.from_bytes(raw_num[:8], "big", signed=True)

            ids.append(chat_id)
        except Exception:
            pass

    return list(dict.fromkeys(ids))


def print_login_chat_summary(raw: bytes) -> list[int]:
    chats_count = None

    marker = b"\xa5chats\xdc"
    pos = raw.find(marker)
    if pos != -1 and pos + len(marker) + 2 <= len(raw):
        chats_count = int.from_bytes(raw[pos + len(marker):pos + len(marker) + 2], "big")

    chat_ids = extract_chat_ids_from_login_raw(raw)

    print("\n=== LOGIN CHAT SUMMARY ===")
    if chats_count is not None:
        print(f"Сервер вернул chats count: {chats_count}")

    if not chat_ids:
        print("chatId через raw extractor не найдены")
        return []

    for i, chat_id in enumerate(chat_ids, 1):
        print(f"{i}. chatId={chat_id}")

    return chat_ids


def pretty_chat_info(raw: bytes):
    chat_id = read_int_after_key(raw, b"\xa2id")
    chat_type = read_str_after_key(raw, b"\xa4type")
    status = read_str_after_key(raw, b"\xa6status")
    owner = read_int_after_key(raw, b"\xa5owner")
    last_text = read_str_after_key(raw, b"\xa4text")
    modified = read_int_after_key(raw, b"\xa8modified")

    print("\n=== CHAT INFO ===")
    print(f"chatId: {chat_id}")
    print(f"type: {chat_type}")
    print(f"status: {status}")
    print(f"owner: {owner}")

    if modified:
        print(f"modified/raw: {modified}")

    if last_text is not None:
        print(f"lastMessage.text: {last_text!r}")

    print("=================\n")


def find_message_chunks(raw: bytes) -> list[bytes]:
    start = raw.find(b"\xa8messages")
    if start == -1:
        return []

    region = raw[start:]

    # Несколько вариантов начала message object:
    # de 00 XX a2 id  — map16 + id
    # de 00 XX ... a2 id — иногда перед id есть compact bytes
    # a2 id d3 ... a4 time — fallback по id/time
    patterns = [
        rb"\xde\x00[\x04-\x40]\xa2id",
        rb"\xde\x00[\x04-\x40].{0,12}\xa2id",
        rb"\xa2id[\xd2\xd3].{4,8}.{0,80}\xa4time",
    ]

    starts = []

    for pat in patterns:
        for m in re.finditer(pat, region, re.DOTALL):
            starts.append(m.start())

    starts = sorted(set(starts))

    # Убираем вложенные совпадения слишком близко друг к другу
    filtered = []
    for s in starts:
        if not filtered or s - filtered[-1] > 20:
            filtered.append(s)

    chunks = []
    for i, s in enumerate(filtered):
        e = filtered[i + 1] if i + 1 < len(filtered) else len(region)
        chunks.append(region[s:e])

    return chunks


def pretty_history(raw: bytes):
    chunks = find_message_chunks(raw)

    print("\n=== CHAT HISTORY ===")

    if not chunks:
        print("messages не найдены")
        print(raw_ascii(raw)[:3000])
        return

    print(f"messages found: {len(chunks)}")

    for i, chunk in enumerate(chunks, 1):
        msg_id = read_int_after_key(chunk, b"\xa2id")
        msg_type = read_str_after_key(chunk, b"\xa4type")
        sender = read_int_after_key(chunk, b"\xa6sender")
        text = read_str_after_key(chunk, b"\xa4text")
        title = read_str_after_key(chunk, b"\xa5title")
        event = read_str_after_key(chunk, b"\xa5event")
        attach_type = read_str_after_key(chunk, b"\xa5_type")
        base_url = read_str_after_key(chunk, b"\xa7baseUrl")

        print(f"\n#{i}")
        print(f"id: {msg_id}")
        print(f"type: {msg_type}")
        print(f"sender: {sender}")

        if event:
            print(f"event: {event}")

        if text:
            print("text:")
            print(text)
        elif title:
            print("title:")
            print(title)
        else:
            strings = extract_visible_utf8_strings(chunk)
            useful = [
                s for s in strings
                if len(s) >= 4
                and not s.startswith("https://")
                and s not in {"USER", "PHOTO", "CONTROL", "FORWARD"}
            ]
            if useful:
                print("strings:")
                for s in useful[:8]:
                    print("-", s)
            else:
                print("text: <не извлечён>")

        if attach_type:
            print(f"attachment: {attach_type}")

        if base_url:
            print(f"baseUrl: {base_url[:120]}...")

EXPORT_DIR = Path("max_exports")


def ts_ms_to_iso(value: int | None) -> str | None:
    if not value:
        return None

    # В MAX иногда time выглядит нестандартно, поэтому не ломаемся.
    try:
        if value > 10_000_000_000_000:
            value = value // 1000
        elif value > 10_000_000_000:
            pass
        else:
            return None

        return datetime.datetime.fromtimestamp(
            value / 1000,
            tz=datetime.timezone.utc,
        ).isoformat()
    except Exception:
        return None


def clean_text_candidate(s: str) -> str:
    s = re.sub(r"\s+", " ", s).strip()
    return s


def looks_like_noise(s: str) -> bool:
    if not s:
        return True

    bad_exact = {
        "USER",
        "PHOTO",
        "CONTROL",
        "FORWARD",
        "LINK",
        "SHARE",
        "INLINE_KEYBOARD",
        "CLIPBOARD",
        "RIFF",
        "WEBPVP8",
        "reactionInfo",
        "previewData",
        "baseUrl",
        "photoToken",
    }

    if s in bad_exact:
        return True

    if s.startswith("https://i.oneme.ru"):
        return True

    if s.startswith("BTEx"):
        return True

    # Слишком много бинарного мусора/служебных символов.
    weird = sum(1 for ch in s if ord(ch) < 32 and ch not in "\n\r\t")
    if weird:
        return True

    return False


def best_text_from_chunk(chunk: bytes) -> str | None:
    text = read_str_after_key(chunk, b"\xa4text")
    if text:
        return text

    title = read_str_after_key(chunk, b"\xa5title")
    if title:
        return title

    strings = extract_visible_utf8_strings(chunk)

    useful = []
    for s in strings:
        s = clean_text_candidate(s)

        if len(s) < 3:
            continue

        if looks_like_noise(s):
            continue

        # Отбрасываем очень длинные URL/base64-похожие куски.
        if len(s) > 800 and not any("а" <= c.lower() <= "я" for c in s):
            continue

        useful.append(s)

    if not useful:
        return None

    # Часто самый длинный кириллический кусок — это текст сообщения/описание.
    useful.sort(key=len, reverse=True)
    return useful[0]


def message_chunk_to_dict(chat_id: int, chunk: bytes, index: int) -> dict:
    msg_id = read_int_after_key(chunk, b"\xa2id")
    msg_type = read_str_after_key(chunk, b"\xa4type")
    sender = read_int_after_key(chunk, b"\xa6sender")
    time_raw = read_int_after_key(chunk, b"\xa4time")
    cid = read_int_after_key(chunk, b"\xa3cid")
    event = read_str_after_key(chunk, b"\xa5event")
    attach_type = read_str_after_key(chunk, b"\xa5_type")
    base_url = read_str_after_key(chunk, b"\xa7baseUrl")
    text = best_text_from_chunk(chunk)

    return {
        "index": index,
        "chatId": chat_id,
        "messageId": msg_id,
        "cid": cid,
        "timeRaw": time_raw,
        "timeIso": None,
        "type": msg_type,
        "sender": sender,
        "event": event,
        "text": text,
        "attachmentType": attach_type,
        "baseUrl": base_url,
    }


def parse_history_messages(chat_id: int, raw: bytes) -> list[dict]:
    chunks = find_message_chunks(raw)
    messages = []

    for i, chunk in enumerate(chunks, 1):
        messages.append(message_chunk_to_dict(chat_id, chunk, i))

    return messages


def print_messages_human(messages: list[dict]):
    print("\n=== MESSAGES ===")

    if not messages:
        print("Сообщения не найдены.")
        return

    for m in messages:
        print()
        print(f"#{m.get('index')}")
        print(f"chatId: {m.get('chatId')}")
        print(f"messageId: {m.get('messageId')}")
        print(f"sender: {m.get('sender')}")
        print(f"type: {m.get('type')}")

        if m.get("timeIso"):
            print(f"time: {m['timeIso']}")
        elif m.get("timeRaw"):
            print(f"timeRaw: {m['timeRaw']}")

        if m.get("event"):
            print(f"event: {m['event']}")

        if m.get("text"):
            print("text:")
            print(m["text"])
        else:
            print("text: <не извлечён>")

        if m.get("attachmentType"):
            print(f"attachment: {m['attachmentType']}")

        if m.get("baseUrl"):
            print(f"baseUrl: {m['baseUrl'][:160]}...")


def write_jsonl(path: Path, rows: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("a", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def write_txt(path: Path, rows: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("a", encoding="utf-8") as f:
        for m in rows:
            f.write("\n" + "=" * 80 + "\n")
            f.write(f"chatId: {m.get('chatId')}\n")
            f.write(f"messageId: {m.get('messageId')}\n")
            f.write(f"sender: {m.get('sender')}\n")
            f.write(f"type: {m.get('type')}\n")

            if m.get("timeIso"):
                f.write(f"time: {m['timeIso']}\n")
            elif m.get("timeRaw"):
                f.write(f"timeRaw: {m['timeRaw']}\n")

            if m.get("event"):
                f.write(f"event: {m['event']}\n")

            f.write("text:\n")
            f.write((m.get("text") or "<не извлечён>") + "\n")

            if m.get("attachmentType"):
                f.write(f"attachment: {m['attachmentType']}\n")

            if m.get("baseUrl"):
                f.write(f"baseUrl: {m['baseUrl']}\n")

def get_history_page(sock: ssl.SSLSocket, chat_id: int, from_id: int = 0, count: int = 50):
    send_packet(sock, 49, {
        "chatId": chat_id,
        "from": from_id,
        "forward": count,
    })

    for _ in range(20):
        cmd, opcode, decoded, raw = recv_packet(sock, print_body=False)

        if opcode == 49:
            break

        print(f"skip async packet cmd={cmd} opcode={opcode}")
    else:
        raise RuntimeError("Не дождался ответа CHAT_HISTORY opcode=49")

    if cmd != 1:
        raise RuntimeError(f"CHAT_HISTORY failed: {decoded or raw_ascii(raw)}")

    messages = []

    if decoded and isinstance(decoded, dict):
        raw_messages = decoded.get("messages") or []

        for i, m in enumerate(raw_messages, 1):
            if isinstance(m, dict):
                messages.append({
                    "index": i,
                    "chatId": chat_id,
                    "messageId": m.get("id"),
                    "cid": m.get("cid"),
                    "timeRaw": m.get("time"),
                    "timeIso": ts_ms_to_iso(m.get("time")),
                    "type": m.get("type"),
                    "sender": m.get("sender"),
                    "event": m.get("event"),
                    "text": m.get("text"),
                    "attachmentType": None,
                    "baseUrl": None,
                })

    if not messages:
        messages = parse_history_messages(chat_id, raw)
        debug_history_page(raw)
    return messages, raw

def export_chat_history(
    sock: ssl.SSLSocket,
    chat_id: int,
    page_size: int = 50,
    max_pages: int = 200,
    export_dir: Path = EXPORT_DIR,
):
    safe_chat_id = str(chat_id).replace("-", "minus_")
    jsonl_path = export_dir / f"chat_{safe_chat_id}.jsonl"
    txt_path = export_dir / f"chat_{safe_chat_id}.txt"

    # Перезаписываем файлы для новой выгрузки.
    jsonl_path.unlink(missing_ok=True)
    txt_path.unlink(missing_ok=True)

    from_id = 0
    seen_ids = set()
    total = 0

    print(f"\n=== EXPORT CHAT {chat_id} ===")

    for page in range(1, max_pages + 1):
        print(f"page={page}, from={from_id}")

        messages, raw = get_history_page(
            sock=sock,
            chat_id=chat_id,
            from_id=from_id,
            count=page_size,
        )

        raw_path = export_dir / f"chat_{safe_chat_id}_page_{page}_from_{from_id}.bin"
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_bytes(raw)

        # Убираем дубли.
        fresh = []
        for m in messages:
            mid = m.get("messageId")

            if mid is None:
                # Если id не вытащился, всё равно сохраним.
                fresh.append(m)
                continue

            if mid in seen_ids:
                continue

            seen_ids.add(mid)
            fresh.append(m)

        if not fresh:
            print("Пустая страница или только дубли. Останавливаюсь.")
            break

        write_jsonl(jsonl_path, fresh)
        write_txt(txt_path, fresh)
        fallback_path = export_dir / f"chat_{safe_chat_id}_fallback.txt"

        with fallback_path.open("a", encoding="utf-8") as f:
            f.write("\n" + "=" * 80 + "\n")
            f.write(f"page={page}, from={from_id}\n")

            expected_count = get_msgpack_array_len_after_key(raw, b"\xa8messages")
            f.write(f"server messages count: {expected_count}\n")

            strings = extract_visible_utf8_strings(raw)
            for s in strings:
                s = clean_text_candidate(s)
                if (
                        len(s) >= 3
                        and not looks_like_noise(s)
                        and s not in {
                    "messages", "time", "type", "sender", "text", "attaches",
                    "userIds", "_type", "event", "title", "PInfo",
                }
                ):
                    f.write(f"- {s}\n")

        total += len(fresh)

        last_ids = [
            m.get("messageId")
            for m in fresh
            if isinstance(m.get("messageId"), int)
        ]

        if not last_ids:
            print("Не удалось достать messageId для пагинации. Останавливаюсь.")
            break

        new_from_id = last_ids[-1]

        if new_from_id == from_id:
            print("from_id не меняется. Останавливаюсь.")
            break

        from_id = new_from_id

        # Если пришло меньше page_size, вероятно история закончилась.
        if len(fresh) < page_size:
            print("Пришла неполная страница. Вероятно, конец истории.")
            break

    print(f"\nSaved messages: {total}")
    print(f"JSONL: {jsonl_path}")
    print(f"TXT:   {txt_path}")

    return {
        "chatId": chat_id,
        "messages": total,
        "jsonl": str(jsonl_path),
        "txt": str(txt_path),
    }

def test_history_variants(sock, chat_id: int):
    variants = [
        {"chatId": chat_id, "from": 0, "forward": 10},
        {"chatId": chat_id, "from": 0, "backward": 10},
        {"chatId": chat_id, "from": 0, "forward": 50},
        {"chatId": chat_id, "from": 0, "backward": 50},
    ]

    for payload in variants:
        print("\nTRY HISTORY:", payload)
        request_seq = send_packet(sock, 49, payload)

        for _ in range(20):
            cmd, opcode, decoded, raw = recv_packet(sock, print_body=False)
            if opcode == 49:
                break
            print(f"skip async packet cmd={cmd} opcode={opcode}")
        else:
            print("no history response")
            continue

        print("cmd:", cmd, "opcode:", opcode)
        print("decoded:", decoded)
        debug_history_page(raw)

        messages = parse_history_messages(chat_id, raw)
        print_messages_human(messages)
        print_history_text_fallback(raw)

def debug_history_page(raw: bytes):
    print("\n=== HISTORY PAGE DEBUG ===")
    print("raw bytes:", len(raw))
    print("messages key pos:", raw.find(b"\xa8messages"))

    chunks = find_message_chunks(raw)
    print("detected chunks:", len(chunks))

    print("\nVisible strings:")
    strings = extract_visible_utf8_strings(raw)
    for s in strings[:80]:
        if len(s) >= 3 and not looks_like_noise(s):
            print("-", s[:300])

    expected_count = get_msgpack_array_len_after_key(raw, b"\xa8messages")
    print("server messages count:", expected_count)

    print("==========================\n")

def export_all_found_chats(
    sock: ssl.SSLSocket,
    login_raw: bytes,
    page_size: int = 50,
    max_pages_per_chat: int = 200,
):
    chat_ids = print_login_chat_summary(login_raw)

    if not chat_ids:
        print("chatId не найдены. Нечего выгружать.")
        return []

    results = []

    for i, chat_id in enumerate(chat_ids, 1):
        print(f"\n\n### EXPORT {i}/{len(chat_ids)} chatId={chat_id}")

        try:
            result = export_chat_history(
                sock=sock,
                chat_id=chat_id,
                page_size=page_size,
                max_pages=max_pages_per_chat,
            )
            results.append(result)

        except Exception as e:
            print(f"FAILED chatId={chat_id}: {e}")

    summary_path = EXPORT_DIR / "summary.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(
        json.dumps(results, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(f"\nSummary: {summary_path}")

    return results

def pretty_profile(raw: bytes, title: str = "PROFILE"):
    profile_id = read_int_after_key(raw, b"\xa2id")
    name = read_str_after_key(raw, b"\xa4name")
    phone = read_int_after_key(raw, b"\xa5phone")
    update_time = read_int_after_key(raw, b"\xaaupdateTime")
    registration = read_int_after_key(raw, b"\xb0registration")
    account_type = read_str_after_key(raw, b"\xa4type")
    account_status = read_int_after_key(raw, b"\xadaccountStatus")

    print(f"\n=== {title} ===")
    print(f"id: {profile_id}")

    if name:
        print(f"name: {name}")

    if phone:
        print(f"phone/raw: {phone}")

    if account_type:
        print(f"type: {account_type}")

    if account_status is not None:
        print(f"accountStatus: {account_status}")

    if update_time:
        print(f"updateTime/raw: {update_time}")

    if registration:
        print(f"registration/raw: {registration}")

    strings = extract_visible_utf8_strings(raw)
    useful = [
        s for s in strings
        if len(s) >= 3
        and not s.startswith("BTEx")
        and not s.startswith("https://")
    ]

    if useful:
        print("visible strings:")
        for s in useful[:10]:
            print("-", s)

    print("=================\n")


def pretty_2fa_details(raw: bytes):
    enabled = b"\xa7enabled\xc3" in raw
    disabled = b"\xa7enabled\xc2" in raw

    print("\n=== 2FA DETAILS ===")

    if enabled:
        print("password enabled: yes")
    elif disabled:
        print("password enabled: no")
    else:
        print("password enabled: unknown")

    strings = extract_visible_utf8_strings(raw)
    for s in strings:
        if "@" in s:
            print(f"recovery email/raw: {s}")

    print("===================\n")


# ============================================================
# API methods
# ============================================================

def current_profile(sock: ssl.SSLSocket):
    send_packet(sock, 16, {})
    cmd, opcode, decoded, raw = recv_packet(sock)

    if cmd != 1:
        raise RuntimeError(f"PROFILE failed: {decoded or raw_ascii(raw)}")

    return decoded, raw


def contact_info(sock: ssl.SSLSocket, contact_ids: list[int]):
    send_packet(sock, 32, {
        "contactIds": contact_ids,
    })

    cmd, opcode, decoded, raw = recv_packet(sock)

    if cmd != 1:
        raise RuntimeError(f"CONTACT_INFO failed: {decoded or raw_ascii(raw)}")

    return decoded, raw


def contact_info_by_phone(sock: ssl.SSLSocket, phone: str):
    send_packet(sock, 46, {
        "phone": phone,
    })

    cmd, opcode, decoded, raw = recv_packet(sock)

    if cmd != 1:
        raise RuntimeError(f"CONTACT_INFO_BY_PHONE failed: {decoded or raw_ascii(raw)}")

    return decoded, raw


def chat_info(sock: ssl.SSLSocket, chat_ids: list[int]):
    send_packet(sock, 48, {
        "chatIds": chat_ids,
    })

    cmd, opcode, decoded, raw = recv_packet(sock)
    if cmd != 1:
        raise RuntimeError(f"CHAT_INFO failed: {decoded or raw_ascii(raw)}")

    return decoded, raw


def chat_history_forward(sock: ssl.SSLSocket, chat_id: int, count: int = 20):
    send_packet(sock, 49, {
        "chatId": chat_id,
        "from": 0,
        "forward": count,
    })

    cmd, opcode, decoded, raw = recv_packet(sock)
    if cmd != 1:
        raise RuntimeError(f"CHAT_HISTORY failed: {decoded or raw_ascii(raw)}")

    return decoded, raw


def typing(sock: ssl.SSLSocket, chat_id: int, is_typing: bool = True):
    send_packet(sock, 65, {
        "chatId": chat_id,
        "typing": is_typing,
    })

    cmd, opcode, decoded, raw = recv_packet(sock)
    if cmd != 1:
        raise RuntimeError(f"TYPING failed: {decoded or raw_ascii(raw)}")

    return decoded, raw


def send_message(sock: ssl.SSLSocket, chat_id: int, text: str):
    send_packet(sock, 64, {
        "chatId": chat_id,
        "message": {
            "text": text,
        },
        "randomId": int(time.time() * 1000),
    })

    cmd, opcode, decoded, raw = recv_packet(sock)
    if cmd != 1:
        raise RuntimeError(f"MSG_SEND failed: {decoded or raw_ascii(raw)}")

    return decoded, raw


# ============================================================
# 2FA security methods
# ============================================================

def auth_2fa_details(sock: ssl.SSLSocket):
    send_packet(sock, 104, {})
    cmd, opcode, decoded, raw = recv_packet(sock)

    if cmd != 1:
        raise RuntimeError(f"AUTH_2FA_DETAILS failed: {decoded or raw_ascii(raw)}")

    return decoded, raw


def find_track_id(raw: bytes, decoded=None) -> str | None:
    if isinstance(decoded, dict):
        for key in ("trackId", "track_id", "id"):
            value = decoded.get(key)
            if isinstance(value, str) and len(value) >= 20:
                return value

    return find_uuid_in_raw(raw)

def auth_create_track(track_type: int):
    return run_authenticated_call(112, {
        "type": track_type,
    })


def test_auth_create_track():
    """
    AUTH_CREATE_TRACK ждёт short/int type, не string.
    Каждый запрос идёт в новом соединении.
    """
    candidates = list(range(0, 30))

    for track_type in candidates:
        print(f"\nTrying type={track_type}")

        try:
            cmd, opcode, decoded, raw = auth_create_track(track_type)

            print("cmd:", cmd, "opcode:", opcode)
            print(decoded if decoded is not None else raw_ascii(raw)[:2000])

            track_id = find_track_id(raw, decoded)
            if track_id:
                print("FOUND trackId:", track_id)
                print("FOUND type:", track_type)
                return track_id, track_type

            # Если cmd=1, но trackId не найден — тоже интересно
            if cmd == 1:
                print("SUCCESS without visible trackId")
                return None, track_type

        except Exception as e:
            print("failed:", e)

    return None, None

def create_password_track():
    cmd, opcode, decoded, raw = auth_create_track(0)

    print("cmd:", cmd, "opcode:", opcode)
    print(decoded if decoded is not None else raw_ascii(raw)[:2000])

    if cmd != 1:
        raise RuntimeError(f"AUTH_CREATE_TRACK failed: {decoded or raw_ascii(raw)}")

    track_id = find_track_id(raw, decoded)
    if not track_id:
        raise RuntimeError("trackId не найден")

    print("trackId:", track_id)
    return track_id

def auth_check_password_with_track(track_id: str, password: str):
    return run_authenticated_call(113, {
        "trackId": track_id,
        "password": password,
    })


def auth_validate_password(new_password: str, track_id: str | None = None):
    payload = {
        "password": new_password,
    }
    if track_id:
        payload["trackId"] = track_id

    return run_authenticated_call(107, payload)


def auth_validate_hint(hint: str, track_id: str | None = None):
    payload = {
        "hint": hint,
    }
    if track_id:
        payload["trackId"] = track_id

    return run_authenticated_call(108, payload)


def auth_set_2fa(track_id: str, new_password: str, hint: str | None = None):
    payload = {
        "trackId": track_id,
        "password": new_password,
        "expectedCapabilities": ["update_password"],
    }

    if hint:
        payload["hint"] = hint

    return run_authenticated_call(111, payload)


def auth_set_2fa_try_payload(payload: dict):
    return run_authenticated_call(111, payload)

def auth_set_2fa_with_capability_code(
    track_id: str,
    new_password: str,
    hint: str | None,
    capability_code: int,
):
    payload = {
        "trackId": track_id,
        "password": new_password,
        "expectedCapabilities": [capability_code],
    }

    if hint:
        payload["hint"] = hint

    return run_authenticated_call(111, payload)

def interactive_check_current_password():
    track_id = create_password_track()

    password = getpass.getpass("Текущий 2FA-пароль: ")

    cmd, opcode, decoded, raw = auth_check_password_with_track(track_id, password)

    print("\n=== AUTH_CHECK_PASSWORD ===")
    # print("trackType:", track_type)
    print("trackId:", track_id)
    print("cmd:", cmd, "opcode:", opcode)
    print(decoded if decoded is not None else raw_ascii(raw)[:3000])


def interactive_validate_new_password():
    new_password = getpass.getpass("Новый пароль для проверки: ")

    print("\nПробую без trackId...")
    try:
        cmd, opcode, decoded, raw = auth_validate_password(new_password)
        print("cmd:", cmd, "opcode:", opcode)
        print(decoded if decoded is not None else raw_ascii(raw)[:3000])
    except Exception as e:
        print("failed:", e)

    answer = input("Попробовать с AUTH_CREATE_TRACK? y/N: ").strip().lower()
    if answer != "y":
        return

    track_id, track_type = test_auth_create_track()
    if not track_id:
        print("Не удалось получить trackId.")
        return

    cmd, opcode, decoded, raw = auth_validate_password(new_password, track_id)

    print("\n=== AUTH_VALIDATE_PASSWORD with trackId ===")
    print("trackType:", track_type)
    print("trackId:", track_id)
    print("cmd:", cmd, "opcode:", opcode)
    print(decoded if decoded is not None else raw_ascii(raw)[:3000])


def interactive_validate_hint():
    hint = input("Hint для проверки: ").strip()

    print("\nПробую без trackId...")
    try:
        cmd, opcode, decoded, raw = auth_validate_hint(hint)
        print("cmd:", cmd, "opcode:", opcode)
        print(decoded if decoded is not None else raw_ascii(raw)[:3000])
    except Exception as e:
        print("failed:", e)


def interactive_change_2fa():
    print("\nВнимание: это реальная попытка смены 2FA-пароля.")
    print("Сначала будет AUTH_CREATE_TRACK, потом AUTH_CHECK_PASSWORD, потом AUTH_SET_2FA.")
    confirm = input("Напиши CHANGE, чтобы продолжить: ").strip()

    if confirm != "CHANGE":
        print("Отменено.")
        return

    track_id, track_type = test_auth_create_track()
    if not track_id:
        print("Не удалось получить trackId.")
        return

    old_password = getpass.getpass("Текущий 2FA-пароль: ")

    cmd, opcode, decoded, raw = auth_check_password_with_track(track_id, old_password)

    print("\n=== AUTH_CHECK_PASSWORD ===")
    print("trackType:", track_type)
    print("cmd:", cmd, "opcode:", opcode)
    print(decoded if decoded is not None else raw_ascii(raw)[:3000])

    if cmd != 1:
        print("Текущий пароль не подтверждён, смену не продолжаю.")
        return

    new_password = getpass.getpass("Новый 2FA-пароль: ")
    new_password2 = getpass.getpass("Повтори новый 2FA-пароль: ")

    if new_password != new_password2:
        print("Пароли не совпадают.")
        return

    hint = input("Hint, можно пусто: ").strip() or None

    print("\nПробую AUTH_SET_2FA payload #1: {trackId, password, hint}")
    # cmd, opcode, decoded, raw = auth_set_2fa(track_id, new_password, hint)

    cmd, opcode, decoded, raw = auth_set_2fa_with_capability_code(
        track_id=track_id,
        new_password=new_password,
        hint=hint,
        capability_code=1,
    )

    print("cmd:", cmd, "opcode:", opcode)
    print(decoded if decoded is not None else raw_ascii(raw)[:3000])

    if cmd == 1 or (cmd == 0 and opcode == 159):
        print("Похоже, пароль 2FA изменён.")
        return

    print("\n=== AUTH_SET_2FA ===")
    print("cmd:", cmd, "opcode:", opcode)
    print(decoded if decoded is not None else raw_ascii(raw)[:3000])

    if cmd == 1:
        print("Похоже, пароль 2FA изменён.")
        return

    print("\nЕсли сервер сказал, какое поле нужно, пришли ошибку без паролей.")
    print("Скрипт НЕ будет пробовать другие payload автоматически, чтобы случайно не изменить настройки.")

def logout(sock: ssl.SSLSocket):
    send_packet(sock, 20, {})
    cmd, opcode, decoded, raw = recv_packet(sock)
    return cmd, opcode, decoded, raw


def sessions_info(sock: ssl.SSLSocket):
    send_packet(sock, 96, {})
    cmd, opcode, decoded, raw = recv_packet(sock)
    return cmd, opcode, decoded, raw


def sessions_close(sock: ssl.SSLSocket, session_ids: list[int]):
    send_packet(sock, 97, {
        "sessionIds": session_ids,
    })
    cmd, opcode, decoded, raw = recv_packet(sock)
    return cmd, opcode, decoded, raw


def get_msgpack_array_len_after_key(raw: bytes, key: bytes) -> int | None:
    pos = raw.find(key)
    if pos == -1:
        return None

    p = pos + len(key)
    if p >= len(raw):
        return None

    typ = raw[p]

    # fixarray
    if 0x90 <= typ <= 0x9F:
        return typ & 0x0F

    # array16
    if typ == 0xDC and p + 2 < len(raw):
        return int.from_bytes(raw[p + 1:p + 3], "big")

    # array32
    if typ == 0xDD and p + 4 < len(raw):
        return int.from_bytes(raw[p + 1:p + 5], "big")

    return None


def print_history_text_fallback(raw: bytes):
    expected_count = get_msgpack_array_len_after_key(raw, b"\xa8messages")

    print("\n=== HISTORY FALLBACK TEXT ===")

    if expected_count is not None:
        print(f"server messages count: {expected_count}")

    strings = extract_visible_utf8_strings(raw)

    useful = []
    for s in strings:
        s = clean_text_candidate(s)

        if not s:
            continue

        if looks_like_noise(s):
            continue

        if s in {
            "messages", "time", "type", "sender", "text", "attaches",
            "userIds", "_type", "event", "title", "PInfo",
        }:
            continue

        if len(s) < 3:
            continue

        useful.append(s)

    # dedupe с сохранением порядка
    seen = set()
    filtered = []
    for s in useful:
        if s not in seen:
            seen.add(s)
            filtered.append(s)

    for i, s in enumerate(filtered, 1):
        print(f"{i}. {s}")

    print("=============================\n")


# ============================================================
# CLI
# ============================================================

def print_menu():
    print("\nЧто сделать?")
    print("1. CHAT_INFO по chatId")
    print("2. CHAT_HISTORY forward по chatId")
    print("3. TYPING по chatId")
    print("4. SEND_MESSAGE по chatId")
    print("5. Показать найденные chatId из LOGIN")
    print("6. PROFILE текущего аккаунта")
    print("7. CONTACT_INFO по contactId")
    print("8. CONTACT_INFO_BY_PHONE по телефону")
    print("9. AUTH_2FA_DETAILS")
    print("10. AUTH_CREATE_TRACK test")
    print("11. AUTH_CHECK_PASSWORD через trackId")
    print("12. AUTH_VALIDATE_PASSWORD")
    print("13. AUTH_VALIDATE_HINT")
    print("14. AUTH_SET_2FA сменить пароль")
    print("15. LOGOUT текущей сессии")
    print("16. SESSIONS_INFO")
    print("17. SESSIONS_CLOSE по sessionId")
    print("18. EXPORT_HISTORY одного chatId в JSONL/TXT")
    print("19. EXPORT_HISTORY всех найденных chatId")
    print("20. Показать историю chatId в консоли")
    print("21. TEST_HISTORY_VARIANTS")
    print("99. Сбросить сохранённый token")
    print("0. Выход")


def main():
    with connect() as sock:
        init_session(sock)

        token, decoded, login_raw = ensure_logged_in(sock)
        print("LOGIN OK")

        known_chat_ids = print_login_chat_summary(login_raw)

        while True:
            print_menu()
            choice = input("> ").strip()

            if choice == "0":
                break

            if choice == "99":
                delete_token()
                print("Saved token deleted.")
                continue

            if choice == "5":
                known_chat_ids = print_login_chat_summary(login_raw)
                continue

            if choice == "6":
                decoded, raw = current_profile(sock)

                if decoded is not None:
                    print_result("CURRENT_PROFILE", decoded, raw)
                else:
                    pretty_profile(raw, "CURRENT PROFILE")

                continue

            if choice == "7":
                contact_id = int(input("contactId: ").strip())

                decoded, raw = contact_info(sock, [contact_id])

                if decoded is not None:
                    print_result("CONTACT_INFO", decoded, raw)
                else:
                    pretty_profile(raw, "CONTACT INFO")

                continue

            if choice == "8":
                phone = input("phone, например +79001234567: ").strip()

                decoded, raw = contact_info_by_phone(sock, phone)

                if decoded is not None:
                    print_result("CONTACT_INFO_BY_PHONE", decoded, raw)
                else:
                    pretty_profile(raw, "CONTACT INFO BY PHONE")

                continue

            if choice == "9":
                decoded, raw = auth_2fa_details(sock)

                if decoded is not None:
                    print_result("AUTH_2FA_DETAILS", decoded, raw)
                else:
                    pretty_2fa_details(raw)

                continue

            if choice == "10":
                test_auth_create_track()
                continue

            if choice == "11":
                interactive_check_current_password()
                continue

            if choice == "12":
                interactive_validate_new_password()
                continue

            if choice == "13":
                interactive_validate_hint()
                continue

            if choice == "14":
                interactive_change_2fa()
                continue

            if choice == "15":
                cmd, opcode, decoded, raw = logout(sock)

                print("\n=== LOGOUT ===")
                print("cmd:", cmd, "opcode:", opcode)
                print(decoded if decoded is not None else raw_ascii(raw)[:3000])

                delete_token()
                print("Saved token deleted.")
                break

            if choice == "16":
                cmd, opcode, decoded, raw = sessions_info(sock)

                print("\n=== SESSIONS_INFO ===")
                print("cmd:", cmd, "opcode:", opcode)
                print(decoded if decoded is not None else raw_ascii(raw)[:5000])
                continue

            if choice == "17":
                session_id = int(input("sessionId: ").strip())

                cmd, opcode, decoded, raw = sessions_close(sock, [session_id])

                print("\n=== SESSIONS_CLOSE ===")
                print("cmd:", cmd, "opcode:", opcode)
                print(decoded if decoded is not None else raw_ascii(raw)[:3000])
                continue

            if choice == "18":
                chat_id = int(input("chatId: ").strip())

                page_size_raw = input("page_size [50]: ").strip()
                page_size = int(page_size_raw) if page_size_raw else 50

                max_pages_raw = input("max_pages [200]: ").strip()
                max_pages = int(max_pages_raw) if max_pages_raw else 200

                export_chat_history(
                    sock=sock,
                    chat_id=chat_id,
                    page_size=page_size,
                    max_pages=max_pages,
                )
                continue

            if choice == "19":
                page_size_raw = input("page_size [50]: ").strip()
                page_size = int(page_size_raw) if page_size_raw else 50

                max_pages_raw = input("max_pages_per_chat [200]: ").strip()
                max_pages = int(max_pages_raw) if max_pages_raw else 200

                export_all_found_chats(
                    sock=sock,
                    login_raw=login_raw,
                    page_size=page_size,
                    max_pages_per_chat=max_pages,
                )
                continue

            if choice == "20":
                chat_id = int(input("chatId: ").strip())

                count_raw = input("count [50]: ").strip()
                count = int(count_raw) if count_raw else 50

                from_raw = input("from messageId [0]: ").strip()
                from_id = int(from_raw) if from_raw else 0

                messages, raw = get_history_page(
                    sock=sock,
                    chat_id=chat_id,
                    from_id=from_id,
                    count=count,
                )

                print_messages_human(messages)
                continue

            if choice == "21":
                chat_id = int(input("chatId: ").strip())
                test_history_variants(sock, chat_id)
                continue


            if choice not in {"1", "2", "3", "4"}:
                print("Неизвестная команда")
                continue

            chat_id = int(input("chatId: ").strip())

            if choice == "1":
                decoded, raw = chat_info(sock, [chat_id])

                if decoded is not None:
                    print_result("CHAT_INFO", decoded, raw)
                else:
                    pretty_chat_info(raw)

            elif choice == "2":
                count_raw = input("count [20]: ").strip()
                count = int(count_raw) if count_raw else 20

                decoded, raw = chat_history_forward(sock, chat_id, count)

                if decoded is not None:
                    print_result("CHAT_HISTORY_FORWARD", decoded, raw)
                else:
                    pretty_history(raw)

            elif choice == "3":
                decoded, raw = typing(sock, chat_id, True)
                print_result("TYPING", decoded, raw)

            elif choice == "4":
                text = input("Текст: ").strip()
                decoded, raw = send_message(sock, chat_id, text)
                print_result("MESSAGE_SENT", decoded, raw)


if __name__ == "__main__":
    main()
