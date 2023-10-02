import requests
import json
import base64
from django.conf import settings


def send_webhook_event(url, event_type: str, event_data: dict) -> bool:
    body = json.dumps({
        "event": event_type,
        "data": event_data
    }).encode("utf-8")

    sig = settings.WEBHOOK_SECRET_KEY.sign(body)

    try:
        r = requests.post(url, headers={
            "Content-Type": "application/json",
            "X-AS207960-Signature": base64.b64encode(sig).decode("utf-8")
        }, data=body, timeout=5)
        r.raise_for_status()
    except requests.RequestException:
        return False

    return True
