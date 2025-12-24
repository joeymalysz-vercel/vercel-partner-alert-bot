from http.server import BaseHTTPRequestHandler
import os
import json
import time
import hmac
import hashlib

from api._redis import get_redis

SLACK_SIGNING_SECRET = os.environ["SLACK_SIGNING_SECRET"].encode("utf-8")
SLACK_BOT_USER_ID = os.environ["SLACK_BOT_USER_ID"]  # U...
CHANNEL_SET_KEY = "partner_alert_bot:channels"

redis = get_redis()

def verify_slack_signature(headers, body: bytes) -> bool:
    timestamp = headers.get("X-Slack-Request-Timestamp", "")
    signature = headers.get("X-Slack-Signature", "")

    if not timestamp or not signature:
        return False

    try:
        ts_int = int(timestamp)
    except ValueError:
        return False

    # 5-minute replay window
    if abs(time.time() - ts_int) > 60 * 5:
        return False

    basestring = f"v0:{timestamp}:{body.decode('utf-8')}"
    my_sig = "v0=" + hmac.new(
        SLACK_SIGNING_SECRET,
        basestring.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(my_sig, signature)


class handler(BaseHTTPRequestHandler):
    def _send_text(self, text: str, status: int = 200):
        data = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

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

        # Parse JSON first (needed for url_verification)
        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            self._send_text("bad request", status=400)
            return

        # Slack URL verification handshake:
        # Slack expects the raw "challenge" string in the response body
        if payload.get("type") == "url_verification":
            self._send_text(payload.get("challenge", ""), status=200)
            return

        # Slack retries -> respond 200 quickly (idempotent ops anyway)
        if self.headers.get("X-Slack-Retry-Num"):
            self._send_json({"ok": True})
            return

        # Verify signature for real events
        if not verify_slack_signature(self.headers, body):
            self._send_text("invalid signature", status=401)
            return

        event = payload.get("event") or {}
        event_type = event.get("type")
        user = event.get("user")
        channel = event.get("channel")

        # OPTIMAL FILTER:
        # Ignore everything unless it is *our bot* joining/leaving a channel
        if user != SLACK_BOT_USER_ID or not channel:
            self._send_json({"ok": True})
            return

        if event_type == "member_joined_channel":
            redis.sadd(CHANNEL_SET_KEY, channel)
        elif event_type == "member_left_channel":
            redis.srem(CHANNEL_SET_KEY, channel)

        self._send_json({"ok": True})

    def do_GET(self):
        self._send_json({"ok": True, "message": "Events endpoint is up."})
