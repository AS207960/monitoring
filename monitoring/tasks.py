import datetime

import requests
import json
import base64
from django.conf import settings
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from celery import shared_task
from . import models


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


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=None, default_retry_delay=3,
    ignore_result=True
)
def monitor_firing(monitor_id, starts_at: datetime.datetime, annotations: dict):
    monitor_obj = models.Monitor.objects.filter(id=monitor_id).first()  # type: models.Monitor
    if not monitor_obj:
        return

    alert_data = {
        "alert_id": monitor_obj.id,
        "alert_name": monitor_obj.name,
        "alert_type": monitor_obj.get_monitor_type_display(),
        "alert_type_id": monitor_obj.monitor_type,
        "target_id": monitor_obj.target.id,
        "target": f"{monitor_obj.target.name} ({monitor_obj.target.ip_address})",
        "target_name": monitor_obj.target.name,
        "target_ip": monitor_obj.target.ip_address,
        "starts_at": starts_at,
        "annotations": annotations,
    }

    for target in monitor_obj.alert_group.alerttarget_set.all():
        if target.target_type == target.TYPE_EMAIL:
            email_firing.delay(alert_data, target.target_data)
        elif target.target_type == target.TYPE_SMS:
            sms_firing.delay(alert_data, target.target_data)
        elif target.target_type == target.TYPE_PUSHOVER:
            pushover_firing.delay(alert_data, target.target_data)
        elif target.target_type == target.TYPE_DISCORD:
            discord_firing.delay(alert_data, target.target_data)
        elif target.target_type == target.TYPE_SLACK:
            slack_firing.delay(alert_data, target.target_data)
        elif target.target_type == target.TYPE_TELEGRAM:
            telegram_firing.delay(alert_data, target.target_data)
        elif target.target_type == target.TYPE_WEBHOOK:
            webhook_firing.delay(alert_data, target.target_data)


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=None, default_retry_delay=3,
    ignore_result=True
)
def monitor_resolved(monitor_id, annotations: dict):
    monitor_obj = models.Monitor.objects.filter(id=monitor_id).first()  # type: models.Monitor
    if not monitor_obj:
        return

    alert_data = {
        "alert_name": monitor_obj.name,
        "alert_type": monitor_obj.get_monitor_type_display(),
        "target": f"{monitor_obj.target.name} ({monitor_obj.target.ip_address})",
        "annotations": annotations,
    }

    for target in monitor_obj.alert_group.alerttarget_set.all():
        if target.target_type == target.TYPE_EMAIL:
            email_resolved.delay(alert_data, target.target_data)
        elif target.target_type == target.TYPE_SMS:
            sms_resolved.delay(alert_data, target.target_data)
        elif target.target_type == target.TYPE_PUSHOVER:
            pushover_resolved.delay(alert_data, target.target_data)
        elif target.target_type == target.TYPE_DISCORD:
            discord_resolved.delay(alert_data, target.target_data)
        elif target.target_type == target.TYPE_SLACK:
            slack_resolved.delay(alert_data, target.target_data)
        elif target.target_type == target.TYPE_TELEGRAM:
            telegram_resolved.delay(alert_data, target.target_data)
        elif target.target_type == target.TYPE_WEBHOOK:
            webhook_resolved.delay(alert_data, target.target_data)


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=10, default_retry_delay=3,
    ignore_result=True
)
def email_firing(alert_data: dict, target_data: dict):
    html_content = render_to_string("monitoring_email/alert_firing.txt", alert_data)
    txt_content = render_to_string("monitoring_email/alert_firing.html", alert_data)

    email = EmailMultiAlternatives(
        subject=f"Monitor firing - {alert_data['alert_name']}",
        body=txt_content,
        to=[target_data["email"]],
    )
    email.attach_alternative(html_content, "text/html")
    email.send()


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=10, default_retry_delay=3,
    ignore_result=True
)
def email_resolved(alert_data: dict, target_data: dict):
    html_content = render_to_string("monitoring_email/alert_resolved.txt", alert_data)
    txt_content = render_to_string("monitoring_email/alert_resolved.html", alert_data)

    email = EmailMultiAlternatives(
        subject=f"Monitor no longer firing - {alert_data['alert_name']}",
        body=txt_content,
        to=[target_data["email"]],
    )
    email.attach_alternative(html_content, "text/html")
    email.send()


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=10, default_retry_delay=3,
    ignore_result=True
)
def sms_firing(alert_data: dict, target_data: dict):
    # TODO: Implement SMS alerts
    pass

@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=10, default_retry_delay=3,
    ignore_result=True
)
def sms_resolved(alert_data: dict, target_data: dict):
    # TODO: Implement SMS alerts
    pass


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=10, default_retry_delay=3,
    ignore_result=True
)
def pushover_firing(alert_data: dict, target_data: dict):
    summary = alert_data["annotations"].get("summary", f"{alert_data['alert_name']} is firing.")
    data = {
        "token": settings.PUSHOVER_TOKEN,
        "user": target_data["user_key"],
        "timestamp": alert_data["starts_at"].timestamp(),
        "title": f"{alert_data['alert_name']} - firing",
        "message": f"{summary}\n"
                   f"Target: {alert_data['target']}\n"
                   f"Monitor type: {alert_data['alert_type']}",
    }

    if target_data["device"]:
        data["device"] = target_data["device"]

    requests.post("https://api.pushover.net/1/messages.json", json=data)


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=10, default_retry_delay=3,
    ignore_result=True
)
def pushover_resolved(alert_data: dict, target_data: dict):
    summary = alert_data["annotations"].get("summary", f"{alert_data['alert_name']} is no longer firing.")
    data = {
        "token": settings.PUSHOVER_TOKEN,
        "user": target_data["user_key"],
        "title": f"{alert_data['alert_name']} - no longer firing",
        "message": f"{summary}\n"
                   f"Target: {alert_data['target']}\n"
                   f"Monitor type: {alert_data['alert_type']}",
    }

    if target_data["device"]:
        data["device"] = target_data["device"]

    requests.post("https://api.pushover.net/1/messages.json", json=data)


def make_discord_fields(alert_data):
    fields = [{
        "name": "Monitor name",
        "value": alert_data["alert_name"],
        "inline": True,
    }, {
        "name": "Monitor type",
        "value": alert_data["alert_type"],
        "inline": True,
    }, {
        "name": "Target",
        "value": alert_data["target"],
        "inline": True,
    }]

    if "summary" in alert_data["annotations"]:
        fields.append({
            "name": "Summary",
            "value": alert_data["annotations"]["summary"],
            "inline": False,
        })

    return fields


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=10, default_retry_delay=3,
    ignore_result=True
)
def discord_firing(alert_data: dict, target_data: dict):
    requests.post(target_data["url"], params={
        "wait": "true"
    }, json={
        "content": f"{alert_data['alert_name']} is firing.",
        "embeds": [{
            "title": "Monitor firing",
            "timestamp": alert_data["starts_at"].isoformat(),
            "color": 0xE53E3E,
            "fields": make_discord_fields(alert_data)
        }]
    })


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=10, default_retry_delay=3,
    ignore_result=True
)
def discord_resolved(alert_data: dict, target_data: dict):
    requests.post(target_data["url"], params={
        "wait": "true"
    }, json={
        "content": f"{alert_data['alert_name']} is no longer firing.",
        "embeds": [{
            "title": "Monitor no longer firing",
            "color": 0x38A169,
            "fields": make_discord_fields(alert_data)
        }]
    })

def make_slack_fields(alert_data):
    fields = [{
        "type": "mrkdwn",
        "text": f"*Monitor name*\n{alert_data['alert_name']}"
    },
    {
        "type": "mrkdwn",
        "text": f"*Monitor type*\n{alert_data['alert_type']}"
    },
    {
        "type": "mrkdwn",
        "text": f"*Target*\n{alert_data['target']}"
    }]

    if "summary" in alert_data["annotations"]:
        fields.append({
            "type": "mrkdwn",
            "text": f"*Summary*\n{alert_data['annotations']['summary']}",
        })

    return fields



@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=10, default_retry_delay=3,
    ignore_result=True
)
def slack_firing(alert_data: dict, target_data: dict):
    requests.post(target_data["url"], params={
        "wait": "true"
    }, json={
        "blocks": [{
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{alert_data['alert_name']} firing"
            }
        }, {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"{alert_data['alert_name']} is firing since "
                        f"<!date^{int(alert_data['starts_at'].timestamp())}^{{date_pretty}} {{time_secs}}|{alert_data['starts_at'].isoformat()}>.",
            }
        }, {
            "type": "section",
            "fields": make_slack_fields(alert_data)
        }],
    })


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=10, default_retry_delay=3,
    ignore_result=True
)
def slack_resolved(alert_data: dict, target_data: dict):
    requests.post(target_data["url"], params={
        "wait": "true"
    }, json={
        "blocks": [{
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{alert_data['alert_name']} no longer firing"
            }
        }, {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"{alert_data['alert_name']} is no longer firing."
            }
        }, {
            "type": "section",
            "fields": make_slack_fields(alert_data)
        }],
    })


def sanitise_telegram_text(text):
    for c in "_*[]()~`>#+-=|{}.!":
        text = text.replace(c, f"\\{c}")
    return text


def make_telegram_text(alert_data):
    alert_name = sanitise_telegram_text(alert_data['alert_name'])
    alert_type = sanitise_telegram_text(alert_data['alert_type'])
    target = sanitise_telegram_text(alert_data["target"])

    text = f"*Monitor name:* {alert_name}\n" \
           f"*Monitor type:* {alert_type}\n" \
           f"*Target:* {target}"

    if "summary" in alert_data["annotations"]:
        text += f"\n*Summary*\n{sanitise_telegram_text(alert_data['annotations']['summary'])}"

    return text


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=10, default_retry_delay=3,
    ignore_result=True
)
def telegram_firing(alert_data: dict, target_data: dict):
    alert_name = sanitise_telegram_text(alert_data['alert_name'])

    requests.post(f"https://api.telegram.org/bot{settings.TELEGRAM_TOKEN}/sendMessage", json={
        "chat_id": target_data["chat_id"],
        "parse_mode": "MarkdownV2",
        "text":  f"*{alert_name} is firing\\.*\n\n" + make_telegram_text(alert_data)
    }).raise_for_status()


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=10, default_retry_delay=3,
    ignore_result=True
)
def telegram_resolved(alert_data: dict, target_data: dict):
    alert_name = sanitise_telegram_text(alert_data['alert_name'])

    requests.post(f"https://api.telegram.org/bot{settings.TELEGRAM_TOKEN}/sendMessage", json={
        "chat_id": target_data["chat_id"],
        "parse_mode": "MarkdownV2",
        "text":  f"*{alert_name} is no longer firing\\.*\n\n" + make_telegram_text(alert_data)
    }).raise_for_status()


def make_webhook_data(alert_data: dict):
    return {
        "id": alert_data["alert_id"],
        "name": alert_data["alert_name"],
        "type": alert_data["alert_type_id"],
        "timestamp": alert_data["starts_at"].isoformat() if "starts_at" in alert_data else None,
        "summary": alert_data["annotations"].get("summary", None),
        "target": {
            "id": alert_data["target_id"],
            "name": alert_data["target_name"],
            "ip": alert_data["target_ip"],
        }
    }


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=10, default_retry_delay=3,
    ignore_result=True
)
def webhook_firing(alert_data: dict, target_data: dict):
    send_webhook_event(target_data["url"], "firing", make_webhook_data(alert_data))


@shared_task(
    autoretry_for=(Exception,), retry_backoff=1, retry_backoff_max=60, max_retries=10, default_retry_delay=3,
    ignore_result=True
)
def webhook_resolved(alert_data: dict, target_data: dict):
    send_webhook_event(target_data["url"], "resolved", make_webhook_data(alert_data))
