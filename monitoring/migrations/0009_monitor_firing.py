# Generated by Django 4.2.5 on 2023-10-03 14:08

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("monitoring", "0008_monitor_alert_group"),
    ]

    operations = [
        migrations.AddField(
            model_name="monitor",
            name="firing",
            field=models.BooleanField(blank=True, default=False),
        ),
    ]
