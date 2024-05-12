from django.urls import path
from .views import (
    CustomPasswordChangeView, 
    CustomPasswordChangeDoneView, 
    Profile, 
    Tips, 
    About, 
    ForgotPassword,
    SetNewPassword,
    OTPView,
    VerifyOTPView,
    Enable2FAView,
    MyLoginView,
    OTPVerificationView,
    Disable2FAView
)

urlpatterns = [
    path('verify_otp/',VerifyOTPView.as_view(), name='verify_otp'),
    path('otp', OTPView.as_view(), name='otp'),
    path('forgot_password', ForgotPassword.as_view(), name='forgot_password'),
    path('set_new_password', SetNewPassword.as_view(), name='set_new_password'),
    path('password/change', CustomPasswordChangeView.as_view(), name='password_change'),
    path('password/change/done', CustomPasswordChangeDoneView.as_view(), name='password_change_done'),
    path('profile', Profile.as_view(), name='profile'),
    path('tips', Tips.as_view(), name='tips'),
    path('about', About.as_view(), name='about'),
    path('enable_2fa', Enable2FAView.as_view(), name='enable_2fa'),
    path('users_login',MyLoginView.as_view(), name='users_login'),
    path('otp_verification', OTPVerificationView.as_view(), name='otp_verrification'),
    path('disable_2fa', Disable2FAView.as_view(), name='disable_2fa'),
]
