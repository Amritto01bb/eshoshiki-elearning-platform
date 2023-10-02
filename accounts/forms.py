import re
import secrets

from allauth.account.adapter import get_adapter as get_account_adapter
from allauth.account.utils import user_username, user_email, user_field
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.utils import (
    get_user_model,
    valid_email_or_none,
)
from django import forms
from django.contrib.auth import password_validation, authenticate
from django.contrib.auth.forms import AuthenticationForm, PasswordResetForm, UsernameField
from django.core.exceptions import ValidationError, FieldDoesNotExist
from django.utils.translation import gettext_lazy as _
from .models import Account
from .views import *
from .utils import send_approval_email


class AccountForm(forms.ModelForm):
    error_messages = {'password_mismatch': _("The two password fields didn't match.")}
    main_pass = forms.CharField(label=_("Password"), strip=False, widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}), help_text=password_validation.password_validators_help_text_html())
    confirm_pass = forms.CharField(label=_("Confirm Password"), strip=False, widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}), help_text=_("Enter the same password as before, for verification."))

    class Meta:
        model = Account
        fields = ('first_name', 'last_name', 'username', 'email', 'phone', 'main_pass', 'confirm_pass')
        field_classes = {'username': UsernameField}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self._meta.model.USERNAME_FIELD in self.fields:
            self.fields[self._meta.model.USERNAME_FIELD].widget.attrs['autofocus'] = True

    def clean_username(self):
        username = self.cleaned_data.get("username")
        try:
            account = Account.objects.exclude(id=self.instance.id).get(username=username)
        except Account.DoesNotExist:
            return username
        raise forms.ValidationError('Username "%s" is already in use.' % username)

    def clean_email(self):
        email = self.cleaned_data.get("email").lower()
        try:
            account = Account.objects.exclude(id=self.instance.id).get(email=email)
        except Account.DoesNotExist:
            return email
        raise forms.ValidationError('Email "%s" is already in use.' % email)

    def clean_confirm_pass(self):
        main_pass = self.cleaned_data.get("main_pass")
        confirm_pass = self.cleaned_data.get("confirm_pass")
        if main_pass and confirm_pass and main_pass != confirm_pass:
            raise ValidationError(self.error_messages['password_mismatch'], code='password_mismatch')
        return main_pass

    def _post_clean(self):
        super()._post_clean()
        password = self.cleaned_data.get('main_pass')
        if password:
            try:
                password_validation.validate_password(password, self.instance)
            except ValidationError as error:
                self.add_error('main_pass', error)

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data.get('main_pass'))
        if commit:
            user.save()
        return user


class AccountUpdateForm(forms.ModelForm):
    initial = {}

    class Meta:
        model = Account
        fields = ('first_name', 'last_name')

    def set_initial(self, initial):
        self.initial = initial

    def save(self, commit=True):
        account = super(AccountUpdateForm, self).save(commit=False)

        fname = self.cleaned_data['fname']
        lname = self.cleaned_data['lname']

        if fname and fname != '':
            account.fname = fname
        else:
            account.fname = self.initial['fname']

        if lname and lname != '':
            account.lname = lname
        else:
            account.lname = self.initial['lname']

        if commit:
            account.save()
        return account


def validate_authentication(request, username, email, password):
    user = None
    user_pk = None
    if email and email.strip() != '':
        user_pk = email
    elif username and username.strip() != '':
        user_pk = username

    if not user_pk and not password:
        return user

    email_regex = r"^[a-z0-9._-]+@[a-z0-9.]+\.[a-z]{2,15}$"
    if re.match(email_regex, user_pk):
        user = authenticate(request, email=user_pk, password=password)
    else:
        username_regex = r"^[a-z0-9_]{5,30}$"
        if re.match(username_regex, user_pk):
            user = authenticate(request, username=user_pk, password=password)

    return user


class AccountAuthenticationForm(AuthenticationForm):
    username = UsernameField(label="Username", max_length=255, widget=forms.TextInput(attrs={"autofocus": True}), required=False)
    email = forms.EmailField(label="Email", max_length=255, widget=forms.EmailInput, required=False)
    password = forms.CharField(label="Password", max_length=255, strip=False, widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}))

    def __init__(self, request=None, *args, **kwargs):
        self.request = request
        self.user_cache = None
        super().__init__(*args, **kwargs)

        self.fields = {'username': self.fields.pop('username'), 'email': self.fields.pop('email'), 'password': self.fields.pop('password')}
        self.error_messages["invalid_login"] = "Please enter the correct credentials. Note that both fields may be case-sensitive."

    def clean(self):
        username = self.cleaned_data.get("username")
        email = self.cleaned_data.get("email")
        password = self.cleaned_data.get("password")
        if not username and not email:
            raise forms.ValidationError("Please provide either an username or email.")

        self.user_cache = validate_authentication(self.request, username, email, password)
        if self.user_cache is None:
            raise self.get_invalid_login_error()
        elif self.user_cache.is_verified and not self.user_cache.is_active:
            self.confirm_login_allowed(self.user_cache)

        return self.cleaned_data

    def get_invalid_login_error(self):
        return ValidationError(self.error_messages["invalid_login"], code="invalid_login")


class EmailValidationOnForgotPassword(PasswordResetForm):
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if not Account.objects.filter(email__iexact=email, is_active=True).exists():
            raise forms.ValidationError("There is no user registered with the specified Email address.")
        return email


# Default Social Account Adapter
def user_bool_field(user, field, *args):
    if not field:
        return
    user_model = get_user_model()
    try:
        field_meta = user_model._meta.get_field(field)
    except FieldDoesNotExist:
        if not hasattr(user, field):
            return
    if args:
        # Setter
        v = args[0]
        setattr(user, field, v)
    else:
        # Getter
        return getattr(user, field)


def make_random_password(length=10, allowed_chars="abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"):
    return "".join(secrets.choice(allowed_chars) for i in range(length))


class CustomDefaultSocialAccountAdapter(DefaultSocialAccountAdapter):
    def pre_social_login(self, request, sociallogin):
        user = sociallogin.user
        if sociallogin.is_existing:
            return

        try:
            user = Account.objects.get(email=user.email)
            sociallogin.connect(request, user)
        except Account.DoesNotExist:
            pass

    def save_user(self, request, sociallogin, form=None):
        u = sociallogin.user
        u.set_unusable_password()
        if form:
            get_account_adapter().save_user(request, u, form)
        else:
            get_account_adapter().populate_username(request, u)

        sociallogin.save(request)
        send_approval_email(u, request)
        create_notification(request, u, u.id, "Welcome to Esho Shikhi")
        return u

    def populate_user(self, request, sociallogin, data):
        first_name = data.get("first_name")
        last_name = data.get("last_name")
        name = data.get("name")
        username = data.get("username")
        email = data.get("email")
        phone = data.get("phone")

        user = sociallogin.user

        name_parts = (name or "").partition(" ")
        user_field(user, "first_name", first_name or name_parts[0])
        user_field(user, "last_name", last_name or name_parts[2])
        user_username(user, username or "")
        user_email(user, valid_email_or_none(email) or "")
        user_bool_field(user, "is_verified", True)
        user_bool_field(user, "is_active", True)
        return user

    def get_signup_form_initial_data(self, sociallogin):
        user = sociallogin.user
        initial = {
            "first_name": user_field(user, "first_name") or "",
            "last_name": user_field(user, "last_name") or "",
            "is_verified": user_bool_field(user, "is_verified") or False,
            "is_active": user_bool_field(user, "is_active") or False,
            "username": user_username(user) or "",
            "email": user_email(user) or "",
        }
        return initial
