# Generated by Django 4.2.5 on 2023-09-06 10:06

import as207960_utils.models
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="AlertGroup",
            fields=[
                (
                    "id",
                    as207960_utils.models.TypedUUIDField(
                        data_type="monitoring_alertgroup",
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("name", models.CharField(max_length=255)),
                ("resource_id", models.UUIDField(db_index=True, null=True)),
            ],
            options={
                "ordering": ["name"],
            },
        ),
        migrations.CreateModel(
            name="Monitor",
            fields=[
                (
                    "id",
                    as207960_utils.models.TypedUUIDField(
                        data_type="monitoring_monitor",
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("name", models.CharField(max_length=255)),
                (
                    "monitor_type",
                    models.CharField(
                        choices=[
                            ("ping", "Ping (ICMP)"),
                            ("tcp", "TCP"),
                            ("tls", "TLS"),
                            ("imap", "IMAP"),
                            ("imaps", "IMAPs (TLS)"),
                            ("imapstarttls", "IMAPs (STARTTLS)"),
                            ("pop3", "POP3"),
                            ("pop3s", "POP3s (TLS)"),
                            ("pop3starttls", "POP3s (STARTTLS)"),
                            ("smtp", "SMTP"),
                            ("smtps", "SMTPs (TLS)"),
                            ("smtpstarttls", "SMTPs (STARTTLS)"),
                            ("http", "HTTP"),
                            ("https", "HTTPs"),
                            ("ssh", "SSH"),
                        ],
                        max_length=32,
                    ),
                ),
                ("monitor_data", models.JSONField()),
                ("resource_id", models.UUIDField(db_index=True, null=True)),
            ],
            options={
                "ordering": ["name"],
            },
        ),
        migrations.CreateModel(
            name="Target",
            fields=[
                (
                    "id",
                    as207960_utils.models.TypedUUIDField(
                        data_type="monitoring_target", primary_key=True, serialize=False
                    ),
                ),
                ("name", models.CharField(max_length=255)),
                ("ip_address", models.GenericIPAddressField()),
                ("resource_id", models.UUIDField(db_index=True, null=True)),
            ],
            options={
                "ordering": ["name"],
            },
        ),
        migrations.CreateModel(
            name="MonitorRecipient",
            fields=[
                (
                    "id",
                    as207960_utils.models.TypedUUIDField(
                        data_type="monitoring_monitorrecipient",
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "monitor",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="monitoring.monitor",
                    ),
                ),
                (
                    "recipient",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="monitoring.alertgroup",
                    ),
                ),
            ],
        ),
        migrations.AddField(
            model_name="monitor",
            name="target",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE, to="monitoring.target"
            ),
        ),
        migrations.CreateModel(
            name="AlertTarget",
            fields=[
                (
                    "id",
                    as207960_utils.models.TypedUUIDField(
                        data_type="monitoring_alerttarget",
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "target_type",
                    models.CharField(
                        choices=[
                            ("email", "Email"),
                            ("sms", "SMS"),
                            ("pushover", "Pushover"),
                            ("discord", "Discord"),
                            ("slack", "Slack"),
                            ("telegram", "Telegram"),
                            ("webhook", "Webhook"),
                        ],
                        max_length=32,
                    ),
                ),
                ("target_data", models.JSONField()),
                (
                    "group",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="monitoring.alertgroup",
                    ),
                ),
            ],
        ),
    ]
