# Generated by Django 4.2.5 on 2023-09-06 12:26

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("monitoring", "0004_telegramlinkcode_chat_name"),
    ]

    operations = [
        migrations.AlterField(
            model_name="telegramlinkcode",
            name="chat_name",
            field=models.TextField(blank=True, null=True),
        ),
    ]
