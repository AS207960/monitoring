from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="index"),

    path("monitor/new_ping/", views.create_monitor_ping, name="create_monitor_ping"),
    path("monitor/new_tcp/", views.create_monitor_tcp, name="create_monitor_tcp"),
    path("monitor/new_tls/", views.create_monitor_tls, name="create_monitor_tls"),
    path("monitor/new_imap/", views.create_monitor_imap, name="create_monitor_imap"),
    path("monitor/new_pop3/", views.create_monitor_pop3, name="create_monitor_pop3"),
    path("monitor/new_smtp/", views.create_monitor_smtp, name="create_monitor_smtp"),
    path("monitor/new_http/", views.create_monitor_http, name="create_monitor_http"),
    path("monitor/new_ssh/", views.create_monitor_ssh, name="create_monitor_ssh"),
    path("monitor/<monitor_id>/delete/", views.delete_monitor, name="delete_monitor"),

    path("alert_group/new/", views.create_alert_group, name="create_alert_group"),
    path("alert_group/<ag_id>/", views.view_alert_group, name="alert_group"),
    path("alert_group/<ag_id>/delete/", views.delete_alert_group, name="delete_alert_group"),
    path("alert_group/<ag_id>/add_email/", views.alert_group_add_email, name="alert_group_add_email"),
    path("alert_group/<ag_id>/add_sms/", views.alert_group_add_sms, name="alert_group_add_sms"),
    path("alert_group/<ag_id>/add_pushover/", views.alert_group_add_pushover, name="alert_group_add_pushover"),
    path("alert_group/<ag_id>/add_discord/", views.alert_group_add_discord, name="alert_group_add_discord"),
    path("alert_group/<ag_id>/add_slack/", views.alert_group_add_slack, name="alert_group_add_slack"),
    path("alert_group/<ag_id>/add_telegram/", views.alert_group_add_telegram, name="alert_group_add_telegram"),
    path("alert_group/<ag_id>/add_webhook/", views.alert_group_add_webhook, name="alert_group_add_webhook"),
    path("alert_target/<target_id>/delete/", views.alert_group_delete_target, name="alert_group_delete_target"),

    path("monitoring_admin/", views.admin_index, name="admin_index"),
    path("monitoring_admin/target/new/", views.admin_create_target, name="admin_create_target"),
    path("monitoring_admin/target/<target_id>/delete/", views.admin_delete_target, name="admin_delete_target"),

    path("webhook/telegram/", views.telegram_webhook),
    path("webhook/alert/", views.alert_webhook),
    path("blackbox_sd/", views.blackbox_sd),
]

