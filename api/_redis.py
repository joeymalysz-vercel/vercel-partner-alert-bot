import os
from upstash_redis import Redis

def get_redis() -> Redis:
    """
    Vercel KV / Upstash Redis (REST-based, serverless-safe).

    Uses:
      - STORAGE_KV_REST_API_URL
      - STORAGE_KV_REST_API_TOKEN
    """
    url = os.environ.get("STORAGE_KV_REST_API_URL")
    token = os.environ.get("STORAGE_KV_REST_API_TOKEN")

    if not url or not token:
        raise RuntimeError(
            "Missing Vercel KV env vars. "
            "Expected STORAGE_KV_REST_API_URL and STORAGE_KV_REST_API_TOKEN."
        )

    return Redis(url=url, token=token)
