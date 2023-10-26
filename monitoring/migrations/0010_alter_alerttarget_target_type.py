# Generated by Django 4.2.5 on 2023-10-26 19:29

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("monitoring", "0009_monitor_firing"),
    ]

    operations = [
        migrations.AlterField(
            model_name="alerttarget",
            name="target_type",
            field=models.CharField(
                choices=[
                    ("email", "Email"),
                    ("sms", "SMS"),
                    ("pushover", "Pushover"),
                    ("discord", "Discord"),
                    ("slack", "Slack"),
                    ("telegram", "Telegram"),
                    ("webhook", "Webhook"),
                    ("prometheus", "Prometheus"),
                ],
                max_length=32,
            ),
        ),
    ]
