import datetime
import ipaddress
import secrets
import django_keycloak_auth.clients
from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, permission_required
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
from django.core.exceptions import PermissionDenied
import requests
import json
from . import models, forms, tasks


@login_required
def index(request):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)

    targets = models.Target.get_object_list(access_token)
    alert_groups = models.AlertGroup.get_object_list(access_token)
    monitors = models.Monitor.get_object_list(access_token)

    can_create_alert_group = models.AlertGroup.has_class_scope(access_token, 'create')
    can_create_monitor = models.Monitor.has_class_scope(access_token, 'create')

    return render(request, "monitoring/index.html", {
        "targets": targets,
        "alert_groups": alert_groups,
        "monitors": monitors,
        "can_create_alert_group": can_create_alert_group,
        "can_create_monitor": can_create_monitor,
        "access_token": access_token
    })


@login_required
def create_alert_group(request):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)

    if not models.AlertGroup.has_class_scope(access_token, 'create'):
        raise PermissionDenied()

    if request.method == "POST":
        form = forms.CreateAlertGroup(request.POST)
        if form.is_valid():
            ag = models.AlertGroup(
                name=form.cleaned_data["name"],
                user=request.user,
            )
            ag.save()

            return redirect('alert_group', ag.id)
    else:
        form = forms.CreateAlertGroup()

    return render(request, "monitoring/create_alert_group.html", {
        "form": form
    })


@login_required
@permission_required('monitoring.access_admin', raise_exception=True)
def delete_alert_group(request, ag_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    ag_obj = get_object_or_404(models.AlertGroup, id=ag_id)

    if not ag_obj.has_scope(access_token, 'delete'):
        raise PermissionDenied()

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            ag_obj.delete()
            return redirect('index')

    return render(request, "monitoring/delete_alert_group.html", {
        "alert_group": ag_obj,
    })


@login_required
def view_alert_group(request, ag_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    ag_obj = get_object_or_404(models.AlertGroup, id=ag_id)

    if not ag_obj.has_scope(access_token, 'view'):
        raise PermissionDenied()

    can_edit = ag_obj.has_scope(access_token, 'edit')
    targets = ag_obj.alerttarget_set.all()

    return render(request, "monitoring/view_alert_group.html", {
        "alert_group": ag_obj,
        "targets": targets,
        "can_edit": can_edit,
    })


@login_required
def alert_group_delete_target(request, target_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    target_obj = get_object_or_404(models.AlertTarget, id=target_id)
    ag_obj = target_obj.group

    if not ag_obj.has_scope(access_token, 'edit'):
        raise PermissionDenied()

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            target_obj.delete()
            return redirect('alert_group', ag_obj.id)

    return render(request, "monitoring/alert_group_delete_target.html", {
        "alert_group": ag_obj,
        "target": target_obj,
    })


@login_required
def alert_group_add_email(request, ag_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    ag_obj = get_object_or_404(models.AlertGroup, id=ag_id)

    if not ag_obj.has_scope(access_token, 'edit'):
        raise PermissionDenied()

    if request.method == "POST":
        form = forms.AlertGroupAddEmail(request.POST)
        if form.is_valid():
            target = models.AlertTarget(
                group=ag_obj,
                target_type=models.AlertTarget.TYPE_EMAIL,
                target_data={
                    "email": form.cleaned_data["email"]
                }
            )
            target.save()

            return redirect('alert_group', ag_obj.id)
    else:
        form = forms.AlertGroupAddEmail()

    return render(request, "monitoring/alert_group_add_target.html", {
        "title": f"Add an email to alert group {ag_obj.name}",
        "form": form
    })


@login_required
def alert_group_add_sms(request, ag_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    ag_obj = get_object_or_404(models.AlertGroup, id=ag_id)

    if not ag_obj.has_scope(access_token, 'edit'):
        raise PermissionDenied()

    if request.method == "POST":
        form = forms.AlertGroupAddSMS(request.POST)
        if form.is_valid():
            target = models.AlertTarget(
                group=ag_obj,
                target_type=models.AlertTarget.TYPE_SMS,
                target_data={
                    "number": form.cleaned_data["number"].as_e164
                }
            )
            target.save()

            return redirect('alert_group', ag_obj.id)
    else:
        form = forms.AlertGroupAddSMS()

    return render(request, "monitoring/alert_group_add_target.html", {
        "title": f"Add SMS to alert group {ag_obj.name}",
        "form": form
    })


@login_required
def alert_group_add_pushover(request, ag_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    ag_obj = get_object_or_404(models.AlertGroup, id=ag_id)

    if not ag_obj.has_scope(access_token, 'edit'):
        raise PermissionDenied()

    if request.method == "POST":
        form = forms.AlertGroupAddPushover(request.POST)
        if form.is_valid():
            data = {
                "token": settings.PUSHOVER_TOKEN,
                "user": form.cleaned_data["user_key"]
            }
            if form.cleaned_data["device"]:
                data["device"] = form.cleaned_data["device"]

            r = requests.post("https://api.pushover.net/1/users/validate.json", data=data)
            data = r.json()
            if data["status"] != 1:
                if data.get("user") == "invalid":
                    form.add_error('user_key', "Invalid user key")
                if data.get("device") == "invalid for this user":
                    form.add_error('device', "Invalid device name")
            else:
                target = models.AlertTarget(
                    group=ag_obj,
                    target_type=models.AlertTarget.TYPE_PUSHOVER,
                    target_data={
                        "user_key": form.cleaned_data["user_key"],
                        "device": form.cleaned_data["device"] if form.cleaned_data["device"] else None
                    }
                )
                target.save()

                return redirect('alert_group', ag_obj.id)
    else:
        form = forms.AlertGroupAddPushover()

    return render(request, "monitoring/alert_group_add_target.html", {
        "title": f"Add Pushover to alert group {ag_obj.name}",
        "form": form
    })


@login_required
def alert_group_add_discord(request, ag_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    ag_obj = get_object_or_404(models.AlertGroup, id=ag_id)

    if not ag_obj.has_scope(access_token, 'edit'):
        raise PermissionDenied()

    if request.method == "POST":
        form = forms.AlertGroupAddWebhook(request.POST)
        if form.is_valid():
            r = requests.get(form.cleaned_data["webhook_url"])
            if r.status_code != 200:
                form.add_error('webhook_url', "Invalid webhook URL")
            else:
                data = r.json()
                if data.get("type") != 1:
                    form.add_error('webhook_url', "Invalid webhook URL")
                else:
                    target = models.AlertTarget(
                        group=ag_obj,
                        target_type=models.AlertTarget.TYPE_DISCORD,
                        target_data={
                            "url": form.cleaned_data["webhook_url"]
                        }
                    )
                    target.save()

                    return redirect('alert_group', ag_obj.id)
    else:
        form = forms.AlertGroupAddWebhook()

    return render(request, "monitoring/alert_group_add_target.html", {
        "title": f"Add Discord to alert group {ag_obj.name}",
        "form": form
    })


@login_required
def alert_group_add_slack(request, ag_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    ag_obj = get_object_or_404(models.AlertGroup, id=ag_id)

    if not ag_obj.has_scope(access_token, 'edit'):
        raise PermissionDenied()

    if request.method == "POST":
        form = forms.AlertGroupAddWebhook(request.POST)
        if form.is_valid():
            target = models.AlertTarget(
                group=ag_obj,
                target_type=models.AlertTarget.TYPE_SLACK,
                target_data={
                    "url": form.cleaned_data["webhook_url"]
                }
            )
            target.save()

            return redirect('alert_group', ag_obj.id)
    else:
        form = forms.AlertGroupAddWebhook()

    return render(request, "monitoring/alert_group_add_target.html", {
        "title": f"Add Slack to alert group {ag_obj.name}",
        "form": form
    })


@login_required
def alert_group_add_telegram(request, ag_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    ag_obj = get_object_or_404(models.AlertGroup, id=ag_id)

    if not ag_obj.has_scope(access_token, 'edit'):
        raise PermissionDenied()

    if request.method == "POST":
        form = forms.AlertGroupAddTelegram(request.POST)
        if form.is_valid():
            link_code = form.cleaned_data['link_code']
            chat = models.TelegramLinkCode.objects.filter(code=link_code).first()
            if not chat:
                form.add_error('link_code', "Invalid link code")
            else:
                chat.delete()
                target = models.AlertTarget(
                    group=ag_obj,
                    target_type=models.AlertTarget.TYPE_TELEGRAM,
                    target_data={
                        "chat_id": chat.chat_id
                    }
                )
                target.save()

                return redirect('alert_group', ag_obj.id)
    else:
        form = forms.AlertGroupAddTelegram()

    return render(request, "monitoring/alert_group_add_target_telegram.html", {
        "title": f"Add Telegram to alert group {ag_obj.name}",
        "form": form
    })


@login_required
def alert_group_add_webhook(request, ag_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    ag_obj = get_object_or_404(models.AlertGroup, id=ag_id)

    if not ag_obj.has_scope(access_token, 'edit'):
        raise PermissionDenied()

    if request.method == "POST":
        form = forms.AlertGroupAddWebhook(request.POST)
        if form.is_valid():
            url = form.cleaned_data['webhook_url']
            if not url.startswith("https://"):
                form.add_error('webhook_url', "Webhook URL must be HTTPS")
            elif not tasks.send_webhook_event(url, "ping", {}):
                form.add_error('webhook_url', "Failed to send test webhook")
            else:
                target = models.AlertTarget(
                    group=ag_obj,
                    target_type=models.AlertTarget.TYPE_WEBHOOK,
                    target_data={
                        "url": url
                    }
                )
                target.save()

                return redirect('alert_group', ag_obj.id)
    else:
        form = forms.AlertGroupAddWebhook()

    return render(request, "monitoring/alert_group_add_target.html", {
        "title": f"Add webhook to alert group {ag_obj.name}",
        "form": form
    })


@login_required
def alert_group_add_prometheus(request, ag_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    ag_obj = get_object_or_404(models.AlertGroup, id=ag_id)

    if not ag_obj.has_scope(access_token, 'edit'):
        raise PermissionDenied()

    token = secrets.token_hex(16)

    if request.method == "POST":
        new_token = request.POST.get("token")
        if request.POST.get("create") == "true" and new_token:
            target = models.AlertTarget(
                group=ag_obj,
                target_type=models.AlertTarget.TYPE_PROMETHEUS,
                target_data={
                    "token": new_token
                }
            )
            target.save()
            return redirect('alert_group', ag_obj.id)

    return render(request, "monitoring/alert_group_add_target_prometheus.html", {
        "title": f"Add Prometheus metrics to alert group {ag_obj.name}",
        "token": token,
        "external_url": settings.EXTERNAL_URL_BASE
    })


@login_required
@permission_required('monitoring.access_admin', raise_exception=True)
def admin_index(request):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    targets = models.Target.objects.all()

    can_create_target = models.Target.has_class_scope(access_token, "create")

    return render(request, "monitoring/admin_index.html", {
        "targets": targets,
        "can_create_target": can_create_target
    })


@login_required
@permission_required('monitoring.access_admin', raise_exception=True)
def admin_create_target(request):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)

    if not models.Target.has_class_scope(access_token, 'create'):
        raise PermissionDenied()

    if request.method == "POST":
        form = forms.CreateTarget(request.POST)
        if form.is_valid():
            tg = models.Target(
                name=form.cleaned_data["name"],
                ip_address=form.cleaned_data["ip_address"],
                user=form.cleaned_data["user"]
            )
            tg.save()
            print(tg.user, tg.resource_id)

            return redirect('admin_index')
    else:
        form = forms.CreateTarget()

    return render(request, "monitoring/admin_create_target.html", {
        "form": form
    })


@login_required
@permission_required('monitoring.access_admin', raise_exception=True)
def admin_delete_target(request, target_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    target_obj = get_object_or_404(models.Target, id=target_id)

    if not target_obj.has_scope(access_token, 'delete'):
        raise PermissionDenied()

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            target_obj.delete()
            return redirect('admin_index')

    return render(request, "monitoring/admin_delete_target.html", {
        "target": target_obj,
    })


@csrf_exempt
def telegram_webhook(request):
    if request.headers.get("X-Telegram-Bot-Api-Secret-Token") != settings.TELEGRAM_WEBHOOK_TOKEN:
        raise PermissionDenied()

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return HttpResponse("", status=400)

    link_code_obj = None

    if "message" in data:
        if data["message"].get("text") == "/start":
            chat_id = data["message"]["chat"]["id"]
            link_code_obj = models.TelegramLinkCode.objects.get_or_create({
                "code": models.make_id()
            }, chat_id=chat_id)[0]
    if "my_chat_member" in data:
        if data["my_chat_member"]["new_chat_member"]["status"] == "administrator":
            chat_id = data["my_chat_member"]["chat"]["id"]
            link_code_obj = models.TelegramLinkCode.objects.get_or_create({
                "code": models.make_id(),
            }, chat_id=chat_id)[0]

    if link_code_obj:
        requests.post(f"https://api.telegram.org/bot{settings.TELEGRAM_TOKEN}/sendMessage", json={
            "chat_id": link_code_obj.chat_id,
            "protect_content": True,
            "parse_mode": "MarkdownV2",
            "text": f"Your Glauca Monitoring link code is `{link_code_obj.code}`"
        }).raise_for_status()

    return HttpResponse("", status=204)


@login_required
def create_monitor_ping(request):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    can_create_monitor = models.Monitor.has_class_scope(access_token, 'create')

    if not can_create_monitor:
        raise PermissionDenied()

    if request.method == "POST":
        form = forms.CreateMonitorPing(request.POST, user=request.user)
        if form.is_valid():
            monitor = models.Monitor(
                name=form.cleaned_data["name"],
                target=form.cleaned_data["target"],
                alert_group=form.cleaned_data["alert_group"],
                monitor_type=models.Monitor.TYPE_PING,
                monitor_data={},
                user=request.user
            )
            monitor.save()
            return redirect('index')
    else:
        form = forms.CreateMonitorPing(user=request.user)

    return render(request, "monitoring/create_monitor.html", {
        "title": f"Create ping monitor",
        "form": form,
    })


@login_required
def create_monitor_tcp(request):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    can_create_monitor = models.Monitor.has_class_scope(access_token, 'create')

    if not can_create_monitor:
        raise PermissionDenied()

    if request.method == "POST":
        form = forms.CreateMonitorPort(request.POST, user=request.user)
        if form.is_valid():
            monitor = models.Monitor(
                name=form.cleaned_data["name"],
                target=form.cleaned_data["target"],
                alert_group=form.cleaned_data["alert_group"],
                monitor_type=models.Monitor.TYPE_TCP,
                monitor_data={
                    "port": form.cleaned_data["port"]
                },
                user=request.user
            )
            monitor.save()
            return redirect('index')
    else:
        form = forms.CreateMonitorPort(user=request.user)

    return render(request, "monitoring/create_monitor.html", {
        "title": f"Create TCP monitor",
        "form": form,
    })


@login_required
def create_monitor_tls(request):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    can_create_monitor = models.Monitor.has_class_scope(access_token, 'create')

    if not can_create_monitor:
        raise PermissionDenied()

    if request.method == "POST":
        form = forms.CreateMonitorTLS(request.POST, user=request.user)
        if form.is_valid():
            monitor = models.Monitor(
                name=form.cleaned_data["name"],
                target=form.cleaned_data["target"],
                alert_group=form.cleaned_data["alert_group"],
                monitor_type=models.Monitor.TYPE_TLS,
                monitor_data={
                    "port": form.cleaned_data["port"],
                    "hostname": form.cleaned_data["hostname"],
                },
                user=request.user
            )
            monitor.save()
            return redirect('index')
    else:
        form = forms.CreateMonitorTLS(user=request.user)

    return render(request, "monitoring/create_monitor.html", {
        "title": f"Create TLS monitor",
        "form": form,
    })


@login_required
def create_monitor_imap(request):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    can_create_monitor = models.Monitor.has_class_scope(access_token, 'create')

    if not can_create_monitor:
        raise PermissionDenied()

    if request.method == "POST":
        form = forms.CreateMonitorStartTLS(request.POST, user=request.user)
        if form.is_valid():
            monitor = models.Monitor(
                name=form.cleaned_data["name"],
                target=form.cleaned_data["target"],
                alert_group=form.cleaned_data["alert_group"],
                monitor_type=models.Monitor.TYPE_IMAP,
                monitor_data={
                    "port": form.cleaned_data["port"],
                    "tls": form.cleaned_data["tls"],
                    "hostname": form.cleaned_data["hostname"],
                },
                user=request.user
            )
            monitor.save()
            return redirect('index')
    else:
        form = forms.CreateMonitorStartTLS(user=request.user)
        form.fields['port'].initial = 143

    return render(request, "monitoring/create_monitor.html", {
        "title": f"Create IMAP monitor",
        "form": form,
    })


@login_required
def create_monitor_pop3(request):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    can_create_monitor = models.Monitor.has_class_scope(access_token, 'create')

    if not can_create_monitor:
        raise PermissionDenied()

    if request.method == "POST":
        form = forms.CreateMonitorStartTLS(request.POST, user=request.user)
        if form.is_valid():
            monitor = models.Monitor(
                name=form.cleaned_data["name"],
                target=form.cleaned_data["target"],
                alert_group=form.cleaned_data["alert_group"],
                monitor_type=models.Monitor.TYPE_POP3,
                monitor_data={
                    "port": form.cleaned_data["port"],
                    "tls": form.cleaned_data["tls"],
                    "hostname": form.cleaned_data["hostname"],
                },
                user=request.user
            )
            monitor.save()
            return redirect('index')
    else:
        form = forms.CreateMonitorStartTLS(user=request.user)
        form.fields['port'].initial = 110

    return render(request, "monitoring/create_monitor.html", {
        "title": f"Create POP3 monitor",
        "form": form,
    })


@login_required
def create_monitor_smtp(request):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    can_create_monitor = models.Monitor.has_class_scope(access_token, 'create')

    if not can_create_monitor:
        raise PermissionDenied()

    if request.method == "POST":
        form = forms.CreateMonitorStartTLS(request.POST, user=request.user)
        if form.is_valid():
            monitor = models.Monitor(
                name=form.cleaned_data["name"],
                target=form.cleaned_data["target"],
                alert_group=form.cleaned_data["alert_group"],
                monitor_type=models.Monitor.TYPE_SMTP,
                monitor_data={
                    "port": form.cleaned_data["port"],
                    "tls": form.cleaned_data["tls"],
                    "hostname": form.cleaned_data["hostname"],
                },
                user=request.user
            )
            monitor.save()
            return redirect('index')
    else:
        form = forms.CreateMonitorStartTLS(user=request.user)
        form.fields['port'].initial = 25

    return render(request, "monitoring/create_monitor.html", {
        "title": f"Create SMTP monitor",
        "form": form,
    })


@login_required
def create_monitor_http(request):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    can_create_monitor = models.Monitor.has_class_scope(access_token, 'create')

    if not can_create_monitor:
        raise PermissionDenied()

    if request.method == "POST":
        form = forms.CreateMonitorHTTP(request.POST, user=request.user)
        if form.is_valid():
            monitor = models.Monitor(
                name=form.cleaned_data["name"],
                target=form.cleaned_data["target"],
                alert_group=form.cleaned_data["alert_group"],
                monitor_type=models.Monitor.TYPE_HTTP,
                monitor_data={
                    "port": form.cleaned_data["port"],
                    "tls": form.cleaned_data["tls"],
                    "hostname": form.cleaned_data["hostname"],
                },
                user=request.user
            )
            monitor.save()
            return redirect('index')
    else:
        form = forms.CreateMonitorHTTP(user=request.user)
        form.fields['port'].initial = 80

    return render(request, "monitoring/create_monitor.html", {
        "title": f"Create HTTP monitor",
        "form": form,
    })


@login_required
def create_monitor_ssh(request):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    can_create_monitor = models.Monitor.has_class_scope(access_token, 'create')

    if not can_create_monitor:
        raise PermissionDenied()

    if request.method == "POST":
        form = forms.CreateMonitorPort(request.POST, user=request.user)
        if form.is_valid():
            monitor = models.Monitor(
                name=form.cleaned_data["name"],
                target=form.cleaned_data["target"],
                alert_group=form.cleaned_data["alert_group"],
                monitor_type=models.Monitor.TYPE_SSH,
                monitor_data={
                    "port": form.cleaned_data["port"],
                },
                user=request.user
            )
            monitor.save()
            return redirect('index')
    else:
        form = forms.CreateMonitorPort(user=request.user)
        form.fields['port'].initial = 22

    return render(request, "monitoring/create_monitor.html", {
        "title": f"Create SSH monitor",
        "form": form,
    })


@login_required
def delete_monitor(request, monitor_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    monitor_obj = get_object_or_404(models.Monitor, id=monitor_id)

    if not monitor_obj.has_scope(access_token, 'delete'):
        raise PermissionDenied()

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            monitor_obj.delete()
            return redirect('index')

    return render(request, "monitoring/delete_monitor.html", {
        "monitor": monitor_obj,
    })


@csrf_exempt
def blackbox_sd(request):
    authorization_header = request.headers.get("Authorization")
    if not authorization_header:
        return HttpResponse("Authorization header missing", status=401)

    if not authorization_header.startswith("Bearer "):
        return HttpResponse("Authorization header invalid", status=401)

    access_token = authorization_header[7:]

    if not django_keycloak_auth.clients.get_authz_client() \
            .eval_permission(access_token, "service-discovery", "fetch"):
        return HttpResponse("Permission denied", status=403)

    configs = []

    for monitor in models.Monitor.objects.all():
        ip_address = ipaddress.ip_address(monitor.target.ip_address)
        if isinstance(ip_address, ipaddress.IPv6Address):
            formatted_ip = f"[{ip_address}]"
        else:
            formatted_ip = str(ip_address)

        if monitor.monitor_type == models.Monitor.TYPE_PING:
            configs.append({
                "targets": [str(ip_address)],
                "labels": {
                    "monitor_id": str(monitor.id),
                    "monitor": "icmp",
                    "__param_module": "icmp"
                }
            })
        elif monitor.monitor_type == models.Monitor.TYPE_TCP:
            configs.append({
                "targets": [f"{formatted_ip}:{monitor.monitor_data['port']}"],
                "labels": {
                    "monitor_id": str(monitor.id),
                    "monitor": "tcp",
                    "__param_module": "tcp_connect"
                }
            })
        elif monitor.monitor_type == models.Monitor.TYPE_TLS:
            configs.append({
                "targets": [f"{formatted_ip}:{monitor.monitor_data['port']}"],
                "labels": {
                    "monitor_id": str(monitor.id),
                    "monitor": "tls",
                    "__param_module": "tls_connect",
                    "__param_hostname": monitor.monitor_data['hostname']
                }
            })
        elif monitor.monitor_type == models.Monitor.TYPE_IMAP:
            if monitor.monitor_data['tls'] == "none":
                module = "imap"
            elif monitor.monitor_data['tls'] == "tls":
                module = "imap_tls"
            elif monitor.monitor_data['tls'] == "starttls":
                module = "imap_starttls"
            else:
                continue
            configs.append({
                "targets": [f"{formatted_ip}:{monitor.monitor_data['port']}"],
                "labels": {
                    "monitor_id": str(monitor.id),
                    "monitor": "imap",
                    "__param_module": module,
                    "__param_hostname": monitor.monitor_data['hostname']
                }
            })
        elif monitor.monitor_type == models.Monitor.TYPE_POP3:
            if monitor.monitor_data['tls'] == "none":
                module = "pop3"
            elif monitor.monitor_data['tls'] == "tls":
                module = "pop3_tls"
            elif monitor.monitor_data['tls'] == "starttls":
                module = "pop3_starttls"
            else:
                continue
            configs.append({
                "targets": [f"{formatted_ip}:{monitor.monitor_data['port']}"],
                "labels": {
                    "monitor_id": str(monitor.id),
                    "monitor": "pop3",
                    "__param_module": module,
                    "__param_hostname": monitor.monitor_data['hostname']
                }
            })
        elif monitor.monitor_type == models.Monitor.TYPE_SMTP:
            if monitor.monitor_data['tls'] == "none":
                module = "smtp"
            elif monitor.monitor_data['tls'] == "tls":
                module = "smtp_tls"
            elif monitor.monitor_data['tls'] == "starttls":
                module = "smtp_starttls"
            else:
                continue
            configs.append({
                "targets": [f"{formatted_ip}:{monitor.monitor_data['port']}"],
                "labels": {
                    "monitor_id": str(monitor.id),
                    "monitor": "smtp",
                    "__param_module": module,
                    "__param_hostname": monitor.monitor_data['hostname']
                }
            })
        elif monitor.monitor_type == models.Monitor.TYPE_HTTP:
            if monitor.monitor_data['tls']:
                target = f"https://{formatted_ip}:{monitor.monitor_data['port']}"
            elif monitor.monitor_data['tls'] == "tls":
                target = f"http://{formatted_ip}:{monitor.monitor_data['port']}"
            else:
                continue
            configs.append({
                "targets": [target],
                "labels": {
                    "monitor_id": str(monitor.id),
                    "monitor": "http",
                    "__param_module": "http_2xx",
                    "__param_hostname": monitor.monitor_data['hostname']
                }
            })
        elif monitor.monitor_type == models.Monitor.TYPE_SSH:
            configs.append({
                "targets": [f"{formatted_ip}:{monitor.monitor_data['port']}"],
                "labels": {
                    "monitor_id": str(monitor.id),
                    "monitor": "ssh",
                    "__param_module": "ssh_banner"
                }
            })

    return HttpResponse(json.dumps(configs), content_type="application/json")


@csrf_exempt
def alert_webhook(request):
    authorization_header = request.headers.get("Authorization")
    if not authorization_header:
        return HttpResponse("Authorization header missing", status=401)

    if not authorization_header.startswith("Bearer "):
        return HttpResponse("Authorization header invalid", status=401)

    access_token = authorization_header[7:]
    if access_token != settings.ALERT_WEBHOOK_TOKEN:
        return HttpResponse("Permission denied", status=403)

    try:
        alert_data = json.loads(request.body)
    except json.JSONDecodeError:
        return HttpResponse("Invalid JSON", status=429)

    if alert_data["version"] != "4":
        return HttpResponse("Unsupported version", status=429)

    for alert in alert_data["alerts"]:
        monitor = models.Monitor.objects.filter(id=alert["labels"]["monitor_id"]).first() # type: models.Monitor
        if not monitor:
            continue

        if alert["status"] == "firing":
            starts_at = datetime.datetime.strptime(alert["startsAt"], '%Y-%m-%dT%H:%M:%S.%fZ')
            monitor.firing = True
            monitor.save()
            tasks.monitor_firing.delay(monitor.id, starts_at, alert["annotations"])
        elif alert["status"] == "resolved":
            monitor.firing = False
            monitor.save()
            tasks.monitor_resolved.delay(monitor.id, alert["annotations"])

    return HttpResponse("", status=202)


@csrf_exempt
def prometheus_metrics(request):
    authorization_header = request.headers.get("Authorization")
    if not authorization_header:
        return HttpResponse("Authorization header missing", status=401)

    if not authorization_header.startswith("Bearer "):
        return HttpResponse("Authorization header invalid", status=401)

    access_token = authorization_header[7:]
    target = models.AlertTarget.objects.filter(
        target_type=models.AlertTarget.TYPE_PROMETHEUS,
        target_data__token=access_token
    ).first()
    if target is None:
        return HttpResponse("Permission denied", status=403)

    monitors = target.group.monitors.all()
    monitor_ids = []
    for monitor in monitors:
        monitor_ids.append(str(monitor.id))

    monitor_ids = "|".join(monitor_ids)
    r = requests.get(f"{settings.PROMETHEUS_URL}/api/v1/query", headers={
        "X-Scope-OrgID": "as207960"
    }, params={
        "query": f"{{monitor_id=~\"{monitor_ids}\"}}"
    })
    if r.status_code != 200:
        return HttpResponse("Failed to fetch metrics", status=500)

    data = r.json()

    if data["data"]["resultType"] != "vector":
        return HttpResponse("Internal server error", status=500)

    out = []
    for result in data["data"]["result"]:
        name = result["metric"]["__name__"]
        value = result['value'][1]
        if not name.startswith("probe_"):
            continue

        labels = ",".join([f'{k}="{v}"' for k, v in result["metric"].items() if k not in ("__name__", "job")])
        out.append(f"{name}{{{labels}}} {value}")

    return HttpResponse("\n".join(out), content_type="text/plain")