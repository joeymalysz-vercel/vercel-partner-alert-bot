import os
from upstash_redis import Redis

def get_redis() -> Redis:
    url = os.environ.get("STORAGE_KV_REST_API_URL")
    token = os.environ.get("STORAGE_KV_REST_API_TOKEN")

    if not url or not token:
        raise RuntimeError(
            "Missing STORAGE_KV_REST_API_URL / STORAGE_KV_REST_API_TOKEN in env."
        )

    return Redis(url=url, token=token)
