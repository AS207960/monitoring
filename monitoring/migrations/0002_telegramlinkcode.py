# Generated by Django 4.2.5 on 2023-09-06 12:07

import as207960_utils.models
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("monitoring", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="TelegramLinkCode",
            fields=[
                (
                    "id",
                    as207960_utils.models.TypedUUIDField(
                        data_type="monitoring_telegramlinkcode",
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("chat_id", models.IntegerField()),
                ("code", models.CharField(max_length=255, unique=True)),
            ],
        ),
    ]
