from http.server import BaseHTTPRequestHandler
import os
import time
import hmac
import hashlib
import json
import urllib.parse

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

# --- Environment variables from Vercel ---

SLACK_BOT_TOKEN = os.environ["SLACK_BOT_TOKEN"]
SLACK_SIGNING_SECRET = os.environ["SLACK_SIGNING_SECRET"].encode("utf-8")

# Comma-separated list of Slack channel IDs to broadcast into
# Example: BROADCAST_CHANNEL_IDS=C01ABCDEF12,C02GHIJKL34
BROADCAST_CHANNEL_IDS = [
    cid.strip()
    for cid in (os.environ.get("BROADCAST_CHANNEL_IDS") or "").split(",")
    if cid.strip()
]

# Optional: comma-separated list of Slack user IDs allowed to broadcast.
# If empty or not set, ANY user can use /partner_broadcast.
ALLOWED_BROADCASTERS = {
    uid.strip()
    for uid in (os.environ.get("ALLOWED_BROADCASTERS") or "").split(",")
    if uid.strip()
}

slack_client = WebClient(token=SLACK_BOT_TOKEN)


def user_is_allowed(user_id: str) -> bool:
    if not ALLOWED_BROADCASTERS:
        return True
    return user_id in ALLOWED_BROADCASTERS


def verify_slack_signature(headers, body: bytes) -> bool:
    """Verify request signature from Slack."""
    timestamp = headers.get("X-Slack-Request-Timestamp", "")
    signature = headers.get("X-Slack-Signature", "")

    if not timestamp or not signature:
        return False

    # Protect against replay attacks (5 minute window)
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


class handler(BaseHTTPRequestHandler):
    def _send_json(self, payload, status: int = 200):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        # Read body
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length)

        # Verify Slack signature
        if not verify_slack_signature(self.headers, body):
            self._send_json({"error": "invalid request signature"}, status=401)
            return

        # Parse Slack's form-encoded payload
        params = urllib.parse.parse_qs(body.decode("utf-8"))
        command = params.get("command", [""])[0]
        user_id = params.get("user_id", [""])[0]
        text_raw = (params.get("text", [""])[0] or "").strip()

        # Only handle our slash command
        if command != "/partner_broadcast":
            self._send_json({"response_type": "ephemeral", "text": "Unknown command."})
            return

        # Permission check
        if not user_is_allowed(user_id):
            self._send_json(
                {"response_type": "ephemeral", "text": "You are not allowed to use `/partner_broadcast`."}
            )
            return

        # Usage
        if not text_raw:
            self._send_json(
                {
                    "response_type": "ephemeral",
                    "text": (
                        "Usage:\n"
                        "• Preview: `/partner_broadcast Your message here`\n"
                        "• Confirm: `/partner_broadcast CONFIRM: Your message here`"
                    ),
                }
            )
            return

        # Check confirmation prefix
        confirm_prefix = "CONFIRM:"
        is_confirm = False
        if text_raw.upper().startswith(confirm_prefix):
            is_confirm = True
            text = text_raw[len(confirm_prefix):].strip()
        else:
            text = text_raw

        if not text:
            self._send_json(
                {
                    "response_type": "ephemeral",
                    "text": (
                        "Your message is empty after the CONFIRM prefix.\n"
                        "Usage: `/partner_broadcast CONFIRM: Your message here`"
                    ),
                }
            )
            return

        # No channels configured
        if not BROADCAST_CHANNEL_IDS:
            self._send_json(
                {
                    "response_type": "ephemeral",
                    "text": (
                        "No broadcast channels are configured.\n\n"
                        "Set BROADCAST_CHANNEL_IDS in Vercel env variables."
                    ),
                }
            )
            return

        # --- PREVIEW ONLY ---
        if not is_confirm:
            channels_summary = ", ".join(BROADCAST_CHANNEL_IDS)
            self._send_json(
                {
                    "response_type": "ephemeral",
                    "text": (
                        "Preview only — nothing sent.\n\n"
                        f"Message:\n\n{text}\n\n"
                        f"Would be sent to {len(BROADCAST_CHANNEL_IDS)} channel(s):\n"
                        f"{channels_summary}\n\n"
                        "To send, run:\n"
                        f"`/partner_broadcast CONFIRM: {text}`"
                    ),
                }
            )
            return

        # --- CONFIRMED: SEND BROADCAST ---
        sent = 0
        failed = []

        for channel_id in BROADCAST_CHANNEL_IDS:
            try:
                slack_client.chat_postMessage(channel=channel_id, text=text)
                sent += 1
                time.sleep(0.2)
            except SlackApiError as e:
                failed.append(f"{channel_id} ({e.response['error']})")
            except Exception as e:
                failed.append(f"{channel_id} ({e})")

        msg = f"Broadcast complete. Sent to {sent} channel(s)."
        if failed:
            msg += " Failed on: " + ", ".join(failed)

        self._send_json({"response_type": "ephemeral", "text": msg})

    # Optional GET for basic ping
    def do_GET(self):
        self._send_json({"ok": True, "message": "Partner Alert Bot (Vercel) is running."})
