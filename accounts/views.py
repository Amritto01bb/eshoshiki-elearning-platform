import logging
import os

import requests
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.views import PasswordResetView
from django.shortcuts import render, redirect
from django.urls.base import reverse
from django.utils import translation
from django.utils.http import urlsafe_base64_decode
from dotenv import load_dotenv

from .forms import (
    AccountForm, validate_authentication, AccountAuthenticationForm
)
from .models import Account, Token, Notification
from .utils import token_generator, send_verification_email, send_approval_email

load_dotenv()

logger = logging.getLogger(__name__)


# Supporting functions
def get_redirect_if_exists(request):
    is_redirect = None
    if request.GET:
        if request.GET.get("next"):
            is_redirect = str(request.GET.get("next"))

    return is_redirect


def validate_recaptcha(v2_token, v3_token):
    v2_response = requests.post('https://www.google.com/recaptcha/api/siteverify', data={
        'secret': settings.RECAPTCHA_V2_SECRET_KEY,
        'response': v2_token
    }).json()

    v3_response = requests.post('https://www.google.com/recaptcha/api/siteverify', data={
        'secret': settings.RECAPTCHA_V3_SECRET_KEY,
        'response': v3_token
    }).json()

    return v2_response.get('success') and v3_response.get('success') and v3_response.get('score', 0) > 0.5


def verification_user(request, uid_base64, token):
    default_language = 'bn' in translation.get_language()
    context = {"default_language": default_language, 'is_valid_verification_link': False}
    try:
        uid = urlsafe_base64_decode(uid_base64).decode()
        user = Account.objects.get(id=uid)
        token_objects = Token.objects.filter(account=user)
        token_objects = [token_object for token_object in token_objects if token_object.token == token and token_object.is_valid and not token_object.is_expired]
        while len(token_objects) > 0:
            token_object = token_objects.pop()
            context['is_valid_verification_link'] = True
            if token_object.token == token and token_generator.check_token(user, token):
                user.is_verified = True
                user.is_active = True
                user.save()
                token_object.is_valid = False
                token_object.save()
                messages.success(request, 'Email is verified successfully, you can now login')
                send_approval_email(user, request)
                create_notification(request, user, user.id, "Welcome to Esho Shikhi")
                return redirect(reverse('login'))

            token_object.is_valid = False
            token_object.save()
    except Exception as e:
        logger.error(f"Exception occurred in verification user: {e}")

    return render(request, 'emails/verification_failed.html', context)


def signup_page(request, *args, **kwargs):
    if args:
        context = args[0]
    else:
        context = {}

    user = request.user
    if user.is_authenticated:
        messages.error(request, "You are already authenticated as " + str(user.email))
        return redirect('index')

    if request.POST:
        v2_token = request.POST.get('g-recaptcha-response')
        v3_token = request.POST.get('token')
        if validate_recaptcha(v2_token, v3_token):
            if request.POST.get("google_oauth") == "yes":
                return redirect("accounts/google/login/?next=" + reverse('index'))

            form = AccountForm(request.POST)

            if form.is_valid():
                form.save()
                username = form.cleaned_data.get('username')
                email = form.cleaned_data.get('email').lower()
                main_pass = form.cleaned_data.get('main_pass')
                user = validate_authentication(request, username, email, main_pass)
                if user and not user.is_verified:
                    send_verification_email(user, request)

                    destination = get_redirect_if_exists(request)
                    # print(destination)
                    # destination = kwargs.get("next")
                    if destination:
                        return redirect(destination)

                    messages.success(request, "Successfully signup.")
                    return redirect('login')
                else:
                    messages.error(request, 'Invalid user from signup, please try again.')
            else:
                messages.error(request, 'Please try again.')
                context['form'] = form
        else:
            messages.error(request, 'Invalid reCAPTCHA. Please try again.')
            return redirect('login')

    context['RECAPTCHA_V2_SITE_KEY'] = settings.RECAPTCHA_V2_SITE_KEY
    context['RECAPTCHA_V3_SITE_KEY'] = settings.RECAPTCHA_V3_SITE_KEY
    return render(request, "accounts/signup.html", context)


def account_logout(request):
    user = request.user
    if user.is_authenticated:
        logout(request)
        messages.success(request, "Successfully Logged Out.")
    else:
        messages.error(request, "You are already Logged Out.")

    return redirect('login')


def login_page(request, *args, **kwargs):
    if args:
        context = args[0]
    else:
        context = {}

    user = request.user
    if user.is_authenticated:
        messages.error(request, "You are already authenticated as " + str(user.email))
        return redirect('index')

    status_code = 200

    if request.POST:
        v2_token = request.POST.get('g-recaptcha-response')
        v3_token = request.POST.get('token')
        if validate_recaptcha(v2_token, v3_token):
            if request.POST.get("google_oauth") == "yes":
                return redirect("accounts/google/login/?next=" + reverse('index'))

            form = AccountAuthenticationForm(request, data=request.POST)

            if form.is_valid():
                username = form.cleaned_data.get('username')
                email = form.cleaned_data.get('email').lower()
                password = form.cleaned_data.get('password')
                user = validate_authentication(request, username, email, password)

                if user and not user.is_verified:
                    messages.error(request, 'Email is not verified, please check your email inbox.')
                    send_verification_email(user, request)
                    status_code = 401
                elif user:
                    login(request, user)
                    remember_me = request.POST.get('remember_me')
                    request.session['user_id'] = user.id
                    if not remember_me:
                        request.session.set_expiry(0)

                    destination = get_redirect_if_exists(request)
                    if destination:
                        return redirect(destination)

                    messages.success(request, "Successfully logged in.")
                    return redirect('index')
            else:
                messages.error(request, 'Please try again.')
                context['form'] = form
        else:
            messages.error(request, 'Invalid reCAPTCHA. Please try again.')
            return redirect('login')

    context['RECAPTCHA_V2_SITE_KEY'] = settings.RECAPTCHA_V2_SITE_KEY
    context['RECAPTCHA_V3_SITE_KEY'] = settings.RECAPTCHA_V3_SITE_KEY
    return render(request, "accounts/login.html", context, status=status_code)


class CustomPasswordResetView(PasswordResetView):
    def form_valid(self, form):
        opts = {
            "use_https": "https" if self.request.scheme == "https" or os.environ['PRODUCTION'] == 'Yes' else "http",
            "token_generator": self.token_generator,
            "from_email": self.from_email,
            "email_template_name": self.email_template_name,
            "subject_template_name": self.subject_template_name,
            "request": self.request,
            "html_email_template_name": self.html_email_template_name,
            "extra_email_context": self.extra_email_context,
        }
        form.save(**opts)
        return super().form_valid(form)


def create_notification(request, user, account_id, notification):
    notification_for = None
    if user:
        notification_for = user
    elif account_id:
        try:
            notification_for = Account.objects.get(id=account_id)
        except Exception as e:
            logger.error(f"Error from create notification: {e}")

    if notification_for:
        Notification.objects.create(account=notification_for, notification=notification)
        return True

    return False


def notifications_page(request, notification_id=None, context=None):
    if context is None:
        context = {}

    user = request.user
    if user.is_authenticated:
        if request.method == "GET" and notification_id:
            try:
                notification = Notification.objects.get(id=notification_id)
                filters = request.GET.get('read')
                if filters:
                    if filters == "Yes" and not notification.is_read:
                        notification.is_read = True
                        notification.save()
                        messages.success(request, "The notification has been marked as read successfully")
                    elif filters == "No" and notification.is_read:
                        notification.is_read = False
                        notification.save()
                        messages.success(request, "The notification has been marked as unread successfully")
                    else:
                        messages.error(request, "Invalid read request, failed to mark the notification")
            except Exception as e:
                logger.error(f"Error from notifications page: {e}")

            return redirect(reverse('notifications'))
        else:
            notifications = Notification.objects.filter(account=user)
            notifications_count = notifications.count()
            filters = request.GET.get('read')
            if filters:
                if filters == "Mark-all":
                    flag = False
                    for notification in notifications:
                        if not notification.is_read:
                            notification.is_read = True
                            notification.save()
                            flag = True

                    if flag:
                        messages.success(request, "The notifications has been marked as read successfully")

            filters = request.GET.get('tab')
            if filters:
                filters = filters.split(',') if ',' in filters else filters
                if isinstance(filters, list) and len(filters) == 2 and "Newest" in filters and "Unread" in filters:
                    notifications = Notification.objects.filter(account=user).order_by('-timestamp')
                    notifications = [notification for notification in notifications if not notification.is_read]
                    notifications_count = len(notifications)
                elif filters == "Newest":
                    notifications = Notification.objects.filter(account=user).order_by('-timestamp')
                    notifications_count = notifications.count()
                elif filters == "Unread":
                    notifications = Notification.objects.filter(account=user)
                    notifications = [notification for notification in notifications if not notification.is_read]
                    notifications_count = len(notifications)
                else:
                    messages.error(request, "Invalid tab request, failed to load the notifications")
                    return redirect(reverse("notifications"))

            context["notifications"] = notifications
            context["notifications_count"] = notifications_count
            return render(request, 'accounts/notifications.html', context)

    messages.error(request, "You are not allow to visit the page")
    return redirect(reverse('index'))
