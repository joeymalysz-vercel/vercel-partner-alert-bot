from http.server import BaseHTTPRequestHandler
import os
import time
import hmac
import hashlib
import json
import urllib.parse

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from api._redis import get_redis

# --- Required env vars ---
SLACK_BOT_TOKEN = os.environ["SLACK_BOT_TOKEN"]
SLACK_SIGNING_SECRET = os.environ["SLACK_SIGNING_SECRET"].encode("utf-8")

# --- Optional env vars ---
ALLOWED_BROADCASTERS = {
    uid.strip()
    for uid in (os.environ.get("ALLOWED_BROADCASTERS") or "").split(",")
    if uid.strip()
}

# High cap by default; set MAX_BROADCAST_CHANNELS=1000 if you want
MAX_BROADCAST_CHANNELS = int(os.environ.get("MAX_BROADCAST_CHANNELS", "500"))

# Optional anti-spam cooldown per user (seconds). 0 disables.
BROADCAST_COOLDOWN_SECONDS = int(os.environ.get("BROADCAST_COOLDOWN_SECONDS", "0"))

# Throttle between sends (seconds) to smooth bursts
POST_THROTTLE_SECONDS = float(os.environ.get("POST_THROTTLE_SECONDS", "0.2"))

CHANNEL_SET_KEY = "partner_alert_bot:channels"

slack_client = WebClient(token=SLACK_BOT_TOKEN)
redis = get_redis()


def user_is_allowed(user_id: str) -> bool:
    if not ALLOWED_BROADCASTERS:
        return True
    return user_id in ALLOWED_BROADCASTERS


def verify_slack_signature(headers, body: bytes) -> bool:
    timestamp = headers.get("X-Slack-Request-Timestamp", "")
    signature = headers.get("X-Slack-Signature", "")

    if not timestamp or not signature:
        return False

    try:
        ts_int = int(timestamp)
    except ValueError:
        return False

    if abs(time.time() - ts_int) > 60 * 5:
        return False

    basestring = f"v0:{timestamp}:{body.decode('utf-8')}"
    my_sig = "v0=" + hmac.new(
        SLACK_SIGNING_SECRET,
        basestring.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(my_sig, signature)


def load_channel_ids() -> list[str]:
    raw = redis.smembers(CHANNEL_SET_KEY) or []
    # Normalize potential bytes -> str
    channel_ids = [
        c.decode("utf-8") if isinstance(c, (bytes, bytearray)) else str(c)
        for c in raw
    ]
    # stable ordering helps previews look consistent
    channel_ids.sort()
    return channel_ids


def cooldown_key(user_id: str) -> str:
    return f"partner_alert_bot:cooldown:{user_id}"


def user_in_cooldown(user_id: str) -> bool:
    if BROADCAST_COOLDOWN_SECONDS <= 0:
        return False
    existing = redis.get(cooldown_key(user_id))
    return existing is not None


def set_cooldown(user_id: str):
    if BROADCAST_COOLDOWN_SECONDS <= 0:
        return
    # store a simple timestamp; TTL enforces cooldown
    redis.set(cooldown_key(user_id), str(int(time.time())), ex=BROADCAST_COOLDOWN_SECONDS)


def post_with_rate_limit_retry(channel_id: str, text: str) -> tuple[bool, str | None]:
    """
    Returns (ok, error). Retries once if Slack rate-limits with Retry-After.
    """
    try:
        slack_client.chat_postMessage(channel=channel_id, text=text)
        return True, None
    except SlackApiError as e:
        err = e.response.get("error")
        if err == "ratelimited":
            # Slack includes Retry-After header in seconds
            retry_after = 1
            try:
                retry_after = int(e.response.headers.get("Retry-After", "1"))
            except Exception:
                retry_after = 1

            time.sleep(retry_after + 1)

            # retry once
            try:
                slack_client.chat_postMessage(channel=channel_id, text=text)
                return True, None
            except SlackApiError as e2:
                return False, e2.response.get("error") or "ratelimited"
        return False, err or "SlackApiError"
    except Exception as e:
        return False, str(e)


class handler(BaseHTTPRequestHandler):
    def _send_json(self, payload, status: int = 200):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length)

        if not verify_slack_signature(self.headers, body):
            self._send_json({"error": "invalid request signature"}, status=401)
            return

        params = urllib.parse.parse_qs(body.decode("utf-8"))
        command = params.get("command", [""])[0]
        user_id = params.get("user_id", [""])[0]
        text_raw = (params.get("text", [""])[0] or "").strip()

        if command != "/partner_broadcast":
            self._send_json({"response_type": "ephemeral", "text": "Unknown command."})
            return

        if not user_is_allowed(user_id):
            self._send_json({
                "response_type": "ephemeral",
                "text": "You are not allowed to use `/partner_broadcast`."
            })
            return

        # Optional status helper
        if text_raw.lower() == "status":
            channel_ids = load_channel_ids()
            self._send_json({
                "response_type": "ephemeral",
                "text": (
                    f"Tracked channels: {len(channel_ids)}\n"
                    + (", ".join(channel_ids) if channel_ids else "(none yet)")
                    + f"\n\nMax cap: {MAX_BROADCAST_CHANNELS}"
                    + (f"\nCooldown: {BROADCAST_COOLDOWN_SECONDS}s" if BROADCAST_COOLDOWN_SECONDS > 0 else "\nCooldown: off")
                )
            })
            return

        if not text_raw:
            self._send_json({
                "response_type": "ephemeral",
                "text": (
                    "Usage:\n"
                    "• Preview: `/partner_broadcast Your message here`\n"
                    "• Confirm: `/partner_broadcast CONFIRM: Your message here`\n"
                    "• Status: `/partner_broadcast status`"
                )
            })
            return

        # Cooldown check (optional)
        if user_in_cooldown(user_id):
            self._send_json({
                "response_type": "ephemeral",
                "text": f"Broadcast cooldown active. Try again in a bit."
            })
            return

        confirm_prefix = "CONFIRM:"
        is_confirm = False
        if text_raw.upper().startswith(confirm_prefix):
            is_confirm = True
            text = text_raw[len(confirm_prefix):].strip()
        else:
            text = text_raw

        if not text:
            self._send_json({
                "response_type": "ephemeral",
                "text": "Empty message. Try again with a message body."
            })
            return

        channel_ids = load_channel_ids()

        if not channel_ids:
            self._send_json({
                "response_type": "ephemeral",
                "text": (
                    "No channels registered yet.\n"
                    "Invite the bot to at least one partner channel, then try again.\n\n"
                    "Tip: `/partner_broadcast status`"
                )
            })
            return

        # Cap enforcement
        if len(channel_ids) > MAX_BROADCAST_CHANNELS:
            self._send_json({
                "response_type": "ephemeral",
                "text": (
                    f"Safety cap triggered: {len(channel_ids)} tracked channels exceeds MAX_BROADCAST_CHANNELS={MAX_BROADCAST_CHANNELS}.\n\n"
                    "Ask the maintainer to raise MAX_BROADCAST_CHANNELS in Vercel env vars if this is expected."
                )
            })
            return

        # Preview-only
        if not is_confirm:
            preview_list = ", ".join(channel_ids[:50])
            more = ""
            if len(channel_ids) > 50:
                more = f"\n…plus {len(channel_ids) - 50} more."

            self._send_json({
                "response_type": "ephemeral",
                "text": (
                    "Preview only — nothing has been sent yet.\n\n"
                    f"Would send to {len(channel_ids)} channel(s).\n"
                    f"{preview_list}{more}\n\n"
                    "If this looks correct, confirm with:\n"
                    f"`/partner_broadcast CONFIRM: {text}`"
                )
            })
            return

        # Confirmed: send broadcast
        set_cooldown(user_id)

        sent = 0
        failed = []

        for channel_id in channel_ids:
            ok, err = post_with_rate_limit_retry(channel_id, text)
            if ok:
                sent += 1
            else:
                failed.append(f"{channel_id} ({err})")
            time.sleep(POST_THROTTLE_SECONDS)

        msg = f"Broadcast complete. Sent to {sent} channel(s)."
        if failed:
            # Keep response short; show first chunk of failures
            head = ", ".join(failed[:20])
            tail = ""
            if len(failed) > 20:
                tail = f" …plus {len(failed) - 20} more."
            msg += f" Failed on {len(failed)}: {head}{tail}"

        self._send_json({"response_type": "ephemeral", "text": msg})

    def do_GET(self):
        self._send_json({"ok": True, "message": "Partner Alert Bot endpoint is up."})
