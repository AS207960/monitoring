from django import forms
from django.core import validators
import phonenumber_field.formfields
import crispy_forms.helper
import crispy_forms.layout
import crispy_forms.bootstrap
import django_keycloak_auth.clients
from . import models


class CreateAlertGroup(forms.Form):
    name = forms.CharField(required=True, validators=[
        validators.MaxLengthValidator(255)
    ])

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-3'
        self.helper.field_class = 'col-lg-9 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            'name'
        )

        self.helper.add_input(crispy_forms.layout.Submit('submit', 'Create'))


class CreateTarget(forms.Form):
    name = forms.CharField(required=True)
    ip_address = forms.GenericIPAddressField(required=True, label='IP Address')
    user = forms.CharField(required=False, label='User ID')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-3'
        self.helper.field_class = 'col-lg-9 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            'name',
            'ip_address',
            'user'
        )

        self.helper.add_input(crispy_forms.layout.Submit('submit', 'Create'))


class AlertGroupAddEmail(forms.Form):
    email = forms.EmailField(required=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-3'
        self.helper.field_class = 'col-lg-9 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            'email'
        )

        self.helper.add_input(crispy_forms.layout.Submit('submit', 'Add'))


class AlertGroupAddSMS(forms.Form):
    number = phonenumber_field.formfields.PhoneNumberField(required=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-3'
        self.helper.field_class = 'col-lg-9 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            'number'
        )

        self.helper.add_input(crispy_forms.layout.Submit('submit', 'Add'))


class AlertGroupAddPushover(forms.Form):
    user_key = forms.CharField(required=True, validators=[
        validators.MaxLengthValidator(255)
    ])
    device = forms.CharField(required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-3'
        self.helper.field_class = 'col-lg-9 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            'user_key',
            'device'
        )

        self.helper.add_input(crispy_forms.layout.Submit('submit', 'Add'))


class AlertGroupAddWebhook(forms.Form):
    webhook_url = forms.URLField(required=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-3'
        self.helper.field_class = 'col-lg-9 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            'webhook_url'
        )

        self.helper.add_input(crispy_forms.layout.Submit('submit', 'Add'))


class AlertGroupAddTelegram(forms.Form):
    link_code = forms.CharField(required=True, validators=[
        validators.MaxLengthValidator(255)
    ])

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-3'
        self.helper.field_class = 'col-lg-9 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            'link_code'
        )

        self.helper.add_input(crispy_forms.layout.Submit('submit', 'Add'))


class CreateMonitorPing(forms.Form):
    name = forms.CharField(required=True)
    target = forms.ModelChoiceField(queryset=None, required=True)

    def __init__(self, *args, user, **kwargs):
        super().__init__(*args, **kwargs)

        access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=user.oidc_profile)
        self.fields['target'].queryset = models.Target.get_object_list(access_token)

        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-3'
        self.helper.field_class = 'col-lg-9 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            'name',
            'target'
        )

        self.helper.add_input(crispy_forms.layout.Submit('submit', 'Create'))


class CreateMonitorPort(forms.Form):
    name = forms.CharField(required=True)
    target = forms.ModelChoiceField(queryset=None, required=True)
    port = forms.IntegerField(required=True, min_value=1, max_value=65535)

    def __init__(self, *args, user, **kwargs):
        super().__init__(*args, **kwargs)

        access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=user.oidc_profile)
        self.fields['target'].queryset = models.Target.get_object_list(access_token)

        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-3'
        self.helper.field_class = 'col-lg-9 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            'name',
            'target',
            'port'
        )

        self.helper.add_input(crispy_forms.layout.Submit('submit', 'Create'))


class CreateMonitorStartTLS(forms.Form):
    name = forms.CharField(required=True)
    target = forms.ModelChoiceField(queryset=None, required=True)
    port = forms.IntegerField(required=True, min_value=1, max_value=65535)
    tls = forms.ChoiceField(required=False, initial=True, label='TLS', choices=(
        ('none', 'None'),
        ('starttls', 'STARTTLS'),
        ('tls', 'TLS')
    ))

    def __init__(self, *args, user, **kwargs):
        super().__init__(*args, **kwargs)

        access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=user.oidc_profile)
        self.fields['target'].queryset = models.Target.get_object_list(access_token)

        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-3'
        self.helper.field_class = 'col-lg-9 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            'name',
            'target',
            'port',
            'tls'
        )

        self.helper.add_input(crispy_forms.layout.Submit('submit', 'Create'))


class CreateMonitorHTTP(forms.Form):
    name = forms.CharField(required=True)
    target = forms.ModelChoiceField(queryset=None, required=True)
    port = forms.IntegerField(required=True, min_value=1, max_value=65535)
    hostname = forms.CharField(required=True)
    tls = forms.BooleanField(required=False, initial=False, label='TLS')

    def __init__(self, *args, user, **kwargs):
        super().__init__(*args, **kwargs)

        access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=user.oidc_profile)
        self.fields['target'].queryset = models.Target.get_object_list(access_token)

        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-3'
        self.helper.field_class = 'col-lg-9 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            'name',
            'target',
            'port',
            'hostname',
            'tls'
        )

        self.helper.add_input(crispy_forms.layout.Submit('submit', 'Create'))