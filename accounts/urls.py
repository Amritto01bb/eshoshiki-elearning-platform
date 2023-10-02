from django.urls import path, re_path
from . import views
from django.contrib.auth import views as auth_views
from .forms import EmailValidationOnForgotPassword



urlpatterns = [
    path('login', views.login_page, name='login'),
    path('signup', views.signup_page, name='signup'),
    path('logout', views.account_logout, name='logout'),

    path('verification/<str:uid_base64>/<str:token>', views.verification_user, name='verification'),

    path('notifications', views.notifications_page, name='notifications'),
    path('notifications/<int:notification_id>', views.notifications_page, name='notifications'),

    path('forget-password/', views.CustomPasswordResetView.as_view(template_name="accounts/change/credentials/forget-password.html", form_class=EmailValidationOnForgotPassword), name="forget-password"),

    path('reset/<uidb64>/<token>/',
         auth_views.PasswordResetConfirmView.as_view(template_name="registration/password_reset_confirm.html"),
         name="password_reset_confirm"),

    path('password_change/', auth_views.PasswordChangeView.as_view(template_name='registration/password_change.html'),
         name='password_change'),

    path('password_change/done/',
         auth_views.PasswordChangeDoneView.as_view(template_name='registration/password_change_done.html'),
         name='password_change_done'),

    path('reset_password_sent/',
         auth_views.PasswordResetDoneView.as_view(template_name="registration/password_reset_done.html"),
         name="password_reset_done"),

    path('reset_password_complete/',
         auth_views.PasswordResetCompleteView.as_view(template_name="registration/password_reset_complete.html"),
         name="password_reset_complete"),

]
