from django.db import models
from django.conf import settings
import phonenumbers
import requests
import django_keycloak_auth.clients
import as207960_utils.models
import base32_crockford
import secrets
import ipaddress


def make_id():
    return f"{base32_crockford.encode(secrets.randbits(64))}"


class AlertGroup(models.Model):
    id = as207960_utils.models.TypedUUIDField("monitoring_alertgroup", primary_key=True)
    name = models.CharField(max_length=255)
    resource_id = models.UUIDField(null=True, db_index=True)

    class Meta:
        ordering = ['name']

    def __init__(self, *args, user=None, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    @classmethod
    def get_object_list(cls, access_token: str, action='view'):
        return cls.objects.filter(resource_id__in=as207960_utils.models.get_object_ids(access_token, 'alert-group', action))

    @classmethod
    def has_class_scope(cls, access_token: str, action='view'):
        scope_name = f"{action}-alert-group"
        return django_keycloak_auth.clients.get_authz_client() \
            .eval_permission(access_token, "alert-group", scope_name)

    def has_scope(self, access_token: str, action='view'):
        scope_name = f"{action}-alert-group"
        return as207960_utils.models.eval_permission(access_token, self.resource_id, scope_name)

    def save(self, *args, **kwargs):
        as207960_utils.models.sync_resource_to_keycloak(
            self,
            display_name="Alert group", scopes=[
                f'view-alert-group',
                f'edit-alert-group',
                f'delete-alert-group',
            ],
            urn="urn:as207960:monitoring:alert_group", super_save=super().save, view_name='alert_group',
            args=args, kwargs=kwargs
        )

    def delete(self, *args, **kwargs):
        super().delete(*args, *kwargs)
        as207960_utils.models.delete_resource(self.resource_id)

    def get_user(self):
        if self.user:
            return self.user
        return as207960_utils.models.get_resource_owner(self.resource_id)

    def __str__(self):
        return self.name


class AlertTarget(models.Model):
    TYPE_EMAIL = "email"
    TYPE_SMS = "sms"
    TYPE_PUSHOVER = "pushover"
    TYPE_DISCORD = "discord"
    TYPE_SLACK = "slack"
    TYPE_TELEGRAM = "telegram"
    TYPE_WEBHOOK = "webhook"
    TYPE_PROMETHEUS = "prometheus"

    TYPES = (
        (TYPE_EMAIL, "Email"),
        (TYPE_SMS, "SMS"),
        (TYPE_PUSHOVER, "Pushover"),
        (TYPE_DISCORD, "Discord"),
        (TYPE_SLACK, "Slack"),
        (TYPE_TELEGRAM, "Telegram"),
        (TYPE_WEBHOOK, "Webhook"),
        (TYPE_PROMETHEUS, "Prometheus"),
    )

    id = as207960_utils.models.TypedUUIDField("monitoring_alerttarget", primary_key=True)
    group = models.ForeignKey(AlertGroup, on_delete=models.CASCADE)
    target_type = models.CharField(max_length=32, choices=TYPES)
    target_data = models.JSONField()

    @property
    def recipient(self):
        if self.target_type == self.TYPE_EMAIL:
            return self.target_data['email']
        elif self.target_type == self.TYPE_SMS:
            return phonenumbers.format_number(
                phonenumbers.parse(self.target_data['number']),
                phonenumbers.PhoneNumberFormat.INTERNATIONAL
            )
        elif self.target_type == self.TYPE_PUSHOVER:
            if self.target_data.get("device"):
                return f"{self.target_data['user']} ({self.target_data['device']})"

            return self.target_data['user_key']
        elif self.target_type == self.TYPE_DISCORD:
            r = requests.get(self.target_data['url'], timeout=5)
            if r.status_code != 200:
                return "Invalid webhook URL"
            else:
                return r.json()["name"]
        elif self.target_type == self.TYPE_SLACK:
            return ""
        elif self.target_type == self.TYPE_TELEGRAM:
            r = requests.get(f"https://api.telegram.org/bot{settings.TELEGRAM_TOKEN}/getChat", params={
                "chat_id": self.target_data['chat_id']
            })
            if r.status_code != 200:
                return "Invalid chat"
            else:
                data = r.json()
                if data["result"]["type"] == "private":
                    return f"@{data['result']['username']}"
                else:
                    return data["result"]["title"]
        elif self.target_type == self.TYPE_WEBHOOK:
            return self.target_data['url']
        elif self.target_type == self.TYPE_PROMETHEUS:
            return f"Access token: {self.target_data['token']}"

    def __str__(self):
        return f"{self.get_target_type_display()} - {self.recipient}"


class Target(models.Model):
    id = as207960_utils.models.TypedUUIDField("monitoring_target", primary_key=True)
    name = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField()
    resource_id = models.UUIDField(null=True, db_index=True)

    class Meta:
        ordering = ['name']

    def __init__(self, *args, user=None, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def __str__(self):
        return f"{self.name} ({self.ip_address})"

    @classmethod
    def get_object_list(cls, access_token: str, action='view'):
        return cls.objects.filter(resource_id__in=as207960_utils.models.get_object_ids(access_token, 'target', action))

    @classmethod
    def has_class_scope(cls, access_token: str, action='view'):
        scope_name = f"{action}-target"
        return django_keycloak_auth.clients.get_authz_client() \
            .eval_permission(access_token, "target", scope_name)

    def has_scope(self, access_token: str, action='view'):
        scope_name = f"{action}-target"
        return as207960_utils.models.eval_permission(access_token, self.resource_id, scope_name)

    def save(self, *args, **kwargs):
        as207960_utils.models.sync_resource_to_keycloak(
            self,
            display_name="Target", scopes=[
                f'view-target',
                f'edit-target',
                f'delete-target',
            ],
            urn="urn:as207960:monitoring:target", super_save=super().save, view_name=None,
            args=args, kwargs=kwargs
        )

    def delete(self, *args, **kwargs):
        super().delete(*args, *kwargs)
        as207960_utils.models.delete_resource(self.resource_id)

    def get_user(self):
        if self.user:
            return self.user
        return as207960_utils.models.get_resource_owner(self.resource_id)

    @property
    def formatted_ip(self):
        ip_address = ipaddress.ip_address(self.ip_address)
        if isinstance(ip_address, ipaddress.IPv6Address):
            return  f"[{ip_address}]"
        else:
            return str(ip_address)



class Monitor(models.Model):
    TYPE_PING = "ping"
    TYPE_TCP = "tcp"
    TYPE_TLS = "tls"
    TYPE_IMAP = "imap"
    TYPE_POP3 = "pop3"
    TYPE_SMTP = "smtp"
    TYPE_HTTP = "http"
    TYPE_SSH = "ssh"
    TYPE_DNS = "dns"
    TYPE_DNS_SECONDARY = "dns-secondary"

    TYPES = (
        (TYPE_PING, "Ping (ICMP)"),
        (TYPE_TCP, "TCP"),
        (TYPE_TLS, "TLS"),
        (TYPE_IMAP, "IMAP"),
        (TYPE_POP3, "POP3"),
        (TYPE_SMTP, "SMTP"),
        (TYPE_HTTP, "HTTP"),
        (TYPE_SSH, "SSH"),
        (TYPE_DNS, "DNS (SOA)"),
        (TYPE_DNS_SECONDARY, "DNS (Secondary)"),
    )

    id = as207960_utils.models.TypedUUIDField("monitoring_monitor", primary_key=True)
    name = models.CharField(max_length=255)
    target = models.ForeignKey(Target, on_delete=models.CASCADE, related_name="monitors")
    alert_group = models.ForeignKey(AlertGroup, on_delete=models.CASCADE, related_name="monitors")
    monitor_type = models.CharField(max_length=32, choices=TYPES)
    monitor_data = models.JSONField()
    firing = models.BooleanField(blank=True, null=False, default=False)
    resource_id = models.UUIDField(null=True, db_index=True)

    class Meta:
        ordering = ['name']

    def __init__(self, *args, user=None, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def __str__(self):
        return f"{self.name} - {self.get_monitor_type_display()} ({self.target.name})"

    @classmethod
    def get_object_list(cls, access_token: str, action='view'):
        return cls.objects.filter(resource_id__in=as207960_utils.models.get_object_ids(access_token, 'monitor', action))

    @classmethod
    def has_class_scope(cls, access_token: str, action='view'):
        scope_name = f"{action}-monitor"
        return django_keycloak_auth.clients.get_authz_client() \
            .eval_permission(access_token, "monitor", scope_name)

    def has_scope(self, access_token: str, action='view'):
        scope_name = f"{action}-monitor"
        return as207960_utils.models.eval_permission(access_token, self.resource_id, scope_name)

    def save(self, *args, **kwargs):
        as207960_utils.models.sync_resource_to_keycloak(
            self,
            display_name="Monitor", scopes=[
                f'view-monitor',
                f'edit-monitor',
                f'delete-monitor',
            ],
            urn="urn:as207960:monitoring:monitor", super_save=super().save, view_name=None,
            args=args, kwargs=kwargs
        )

    def delete(self, *args, **kwargs):
        super().delete(*args, *kwargs)
        as207960_utils.models.delete_resource(self.resource_id)

    def get_user(self):
        if self.user:
            return self.user
        return as207960_utils.models.get_resource_owner(self.resource_id)

    def info(self):
        if self.monitor_type == self.TYPE_PING:
            return ""
        elif self.monitor_type == self.TYPE_TCP:
            return f"Port: {self.monitor_data['port']}"
        elif self.monitor_type == self.TYPE_TLS:
            return (f"Port: {self.monitor_data['port']}\n"
                    f"Hostname: {self.monitor_data['hostname']}")
        elif self.monitor_type == self.TYPE_IMAP:
            return (f"Port: {self.monitor_data['port']}\n"
                    f"TLS: {self.monitor_data['tls']}\n"
                    f"Hostname: {self.monitor_data['hostname']}")
        elif self.monitor_type == self.TYPE_POP3:
            return (f"Port: {self.monitor_data['port']}\n"
                    f"TLS: {self.monitor_data['tls']}\n"
                    f"Hostname: {self.monitor_data['hostname']}")
        elif self.monitor_type == self.TYPE_SMTP:
            return (f"Port: {self.monitor_data['port']}\n"
                    f"TLS: {self.monitor_data['tls']}\n"
                    f"Hostname: {self.monitor_data['hostname']}")
        elif self.monitor_type == self.TYPE_HTTP:
            return (f"Port: {self.monitor_data['port']}\n"
                    f"TLS: {self.monitor_data['tls']}\n"
                    f"Hostname: {self.monitor_data['hostname']}")
        elif self.monitor_type == self.TYPE_SSH:
            return f"Port: {self.monitor_data['port']}"
        elif self.monitor_type == self.TYPE_DNS:
            return (f"Port: {self.monitor_data['port']}\n"
                    f"Zone: {self.monitor_data['zone']}\n"
                    f"Protocol: {self.monitor_data['protocol']}")
        elif self.monitor_type == self.TYPE_DNS_SECONDARY:
            return (f"Port: {self.monitor_data['port']}\n"
                    f"Zone: {self.monitor_data['zone']}\n"
                    f"Primary: {self.monitor_data['primary']}\n"
                    f"Protocol: {self.monitor_data['protocol']}")

class MonitorRecipient(models.Model):
    id = as207960_utils.models.TypedUUIDField("monitoring_monitorrecipient", primary_key=True)
    monitor = models.ForeignKey(Monitor, on_delete=models.CASCADE)
    recipient = models.ForeignKey(AlertGroup, on_delete=models.CASCADE)


class TelegramLinkCode(models.Model):
    id = as207960_utils.models.TypedUUIDField("monitoring_telegramlinkcode", primary_key=True)
    chat_id = models.BigIntegerField()
    code = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return f"{self.chat_id} - {self.code}"
