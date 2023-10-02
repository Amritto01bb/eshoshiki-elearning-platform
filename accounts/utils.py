import os
import threading

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from django.urls.base import reverse
from django.utils import translation
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from djongo.cursor import *

from .models import Account, Token
from .views import *

from dotenv import load_dotenv

load_dotenv()


class TokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return f"{user.id}{timestamp}{user.is_verified}{user.is_active}"


token_generator = TokenGenerator()


def custom_user_display(user):
    return user.email


class EmailThread(threading.Thread):
    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        self.email.send()


def send_verification_email(user, request):
    token_objects = Token.objects.filter(account=user)
    token_objects = [token_object for token_object in token_objects if token_object.is_valid and not token_object.is_expired]
    if len(token_objects) > 0:
        token_object = token_objects.pop()
        uid = urlsafe_base64_encode(force_bytes(user.id))
        token = token_object.token
    else:
        uid = urlsafe_base64_encode(force_bytes(user.id))
        token = token_generator.make_token(user)
        Token.objects.create(account=user, token=token)

    protocol = "https" if request.scheme == "https" or os.environ['PRODUCTION'] == 'Yes' else "http"
    domain = get_current_site(request)

    default_language = 'bn' in translation.get_language()
    context = {"default_language": default_language, 'user': user, "protocol": protocol, 'domain': domain, 'uid': uid, 'token': token}

    email_subject = f"Hi {user.get_name()}, please verify your Esho Shikhi account"
    email_body = render_to_string('emails/verification_email.html', context)
    email = EmailMessage(subject=email_subject, body=email_body, from_email=settings.EMAIL_HOST_USER, to=[user.email])
    email.content_subtype = "html"
    EmailThread(email).start()
    messages.success(request, 'We sent you an email to verify your account.')


def send_approval_email(user, request):
    protocol = "https" if request.scheme == "https" or os.environ['PRODUCTION'] == 'Yes' else "http"
    domain = get_current_site(request)
    context = {'user': user, 'protocol': protocol, 'domain': domain}
    email_subject = f"Hi {user.get_name()}, your Esho Shikhi account has been verified successfully"
    email_body = render_to_string('emails/approval_email.html', context)
    email = EmailMessage(subject=email_subject, body=email_body, from_email=settings.EMAIL_HOST_USER, to=[user.email])
    email.content_subtype = "html"
    EmailThread(email).start()

