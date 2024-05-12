import pyotp
import qrcode
from io import BytesIO
import random
from django.utils import timezone
from django.core.mail import send_mail
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponseRedirect
from django.views.generic import TemplateView, ListView
from django.urls import reverse_lazy, reverse
from django.shortcuts import render, redirect
from allauth.account.views import SignupView, LoginView, PasswordResetView, PasswordChangeView, _ajax_response
from users.models import CustomUser
from users.forms import CustomUserChangeForm, ForgotPasswordForm, SetNewPasswordForm, OTPForm, Enable2FAForm
from django.core.files.base import ContentFile
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.conf import settings


# Create your views here
class MySignupView(SignupView):
    success_url = reverse_lazy('login')
    template_name = 'account/signup.html'


# class MyLoginView(LoginView):
#     template_name = 'account/login.html'

class MyLoginView(LoginView):
    template_name = 'account/login.html'
    input_otp_template = 'account/input_otp_code.html'
    pass_list_template = 'pwdstore/pass_list.html'

    def form_valid(self, form):
        if form.is_valid():
            email = form.cleaned_data.get('login')
            password = form.cleaned_data.get('password')
            user = authenticate(username=email, password=password)
            if user is not None:
                if user.otp_enabled:
                    return render(self.request, self.input_otp_template, {'email': email})
                else:
                    login(self.request, user)
                    return render(self.request, self.pass_list_template)

        return self.form_invalid(form)



class OTPVerificationView(TemplateView):
    template_name = 'account/input_otp_code.html'
    success_template = 'pwdstore/pass_list.html'

    def post(self, request):
        otp_token = request.POST.get('otp_code')
        email = request.POST.get('email')
        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            error_message = "Kindly login again"
            return render(request, self.template_name, {'error_message': error_message})
        otp_base32 = user.otp_base32
        
        totp = pyotp.TOTP(otp_base32)
        if totp.verify(otp_token):
            login(request, user) 
            return render(request, self.success_template)
        error_message = "Invalid OTP. Please try again."
        return render(request, self.template_name, {'error_message': error_message})


class Disable2FAView(TemplateView):
    template_name = 'profile.html'

    def get(self, request):
        user = request.user
        print(user.otp_enabled)
        if user.otp_enabled:
            user.otp_enabled = False
            user.otp_verified = False
            user.otp_base32 = None
            user.otp_auth_url = None
            user.save()
            # Add success message
            messages.success(request, '2FA has been disabled successfully.')
            return render(request, self.template_name)
        else:
            return render(request, self.template_name, {'error_message': '2FA already disabled'})
        

class CustomPasswordChangeView(PasswordChangeView):
    template_name = 'account/password_change.html'
    success_url = reverse_lazy('password_change_done')

    def post(self):
        form_class = self.get_form_class()
        form = self.get_form(form_class)
        if form.is_valid():
            response = self.form_valid(form)
        else:
            response = self.form_invalid(form)
        return _ajax_response(
            self.request, response, form=form, data=self._get_ajax_data_if()  # Provide feedback without a refresh
        )


class CustomPasswordChangeDoneView(TemplateView):
    template_name = 'account/password_change_done.html'


class Profile(LoginRequiredMixin, TemplateView):
    context_object_name = 'data'
    template_name = 'profile.html'

# Shows users current details on the profile page
    def get_context_data(self):
        context = super().get_context_data()
        context['form'] = CustomUserChangeForm(instance=self.request.user)
        context['2fa_enabled'] = self.request.user.otp_enabled
        return context

# If form is valid updated data saved, if not valid form errors display
    def post(self, request):
        # Takes user input saves it if the form is valid
        form = CustomUserChangeForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
        return HttpResponseRedirect(reverse('profile'))


class Tips(TemplateView):
    template_name = "tips.html"


class About(TemplateView):
    template_name = "about.html"



class ForgotPassword(TemplateView):
    template_name = 'account/forgot_password.html'


class ForgotPassword(TemplateView):
    template_name = 'account/forgot_password.html'

    def get(self, request, *args, **kwargs):
        form = ForgotPasswordForm() 
        return render(request, self.template_name, {'form': form})


class OTPView(TemplateView):
    template_name = 'account/otp.html'

    def post(self, request, *args, **kwargs):
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            user = CustomUser.objects.filter(email=email).first()
            if user:
                otp = ''.join([str(random.randint(0, 9)) for _ in range(5)])
                user.otp = otp
                user.otp_created_time = (timezone.now() + timezone.timedelta(minutes=5))
                user.save()

                subject = 'Your OTP for Password Recovery'
                message = f'Your OTP for password recovery is: {otp}. It expires in 5 minutes'
                sender_email = settings.EMAIL_HOST_USER
                recipient_email = user.email
                print(otp)
                send_mail(subject, message, sender_email, [recipient_email], fail_silently=True)
                print(send_mail)
                
                return render(request, self.template_name)
            else:
                return render(request, self.error_template_name, {'error_message': 'User with this email does not exist'})
        else:
            return render(request, self.error_template_name, {'error_message': 'Invalid form data'})

    def get(self, request, *args, **kwargs):
        print('here')
        return render(request, self.template_name, {})
    


class VerifyOTPView(TemplateView):
    template_name = 'account/otp.html'
    error_template_name = 'account/forgot_password.html'
    success_template = 'account/set_new_password.html'

    def post(self, request, *args, **kwargs):
        form = OTPForm(request.POST)
        if form.is_valid():
            otp = form.cleaned_data['otp']
            user = CustomUser.objects.filter(otp=otp).first()
            if user:
                if user.otp_created_time < timezone.now():
                    return render(request, self.template_name, {'error_message': 'Expired OTP'})
                return render(request, self.success_template)
            return render(request, self.error_template_name, {'error_message': 'Invalid OTP'})
        else:
            return render(request, self.error_template_name, {'error_message': 'Invalid OTP'})


class SetNewPassword(TemplateView):
    template_name = 'account/set_new_password.html'
    success_template_name ='account/login.html'

    def get(self, request, *args, **kwargs):
        form = SetNewPasswordForm() 
        return render(request, self.template_name, {'form': form})
    
    def post(self, request, *args, **kwargs):
        form = SetNewPasswordForm(request.POST)
        if form.is_valid():
            password = form.cleaned_data['password']
            confirm_password = form.cleaned_data['confirm_password']
            if password != confirm_password:
                return render(request, self.template_name, {'error_message': 'Passwords do not match'})
            user = CustomUser.objects.filter(otp = request.GET.get('otp')).first()
            user.set_password(password)
            user.otp = None
            user.otp_created_time = None
            user.save()
            return render(request, self.success_template_name)
        else:
            return render(request, self.template_name, {'form': form})
        


class Enable2FAView(TemplateView):
    template_name = 'account/enable_2fa.html'
    error_template = 'profile.html'

    def get(self, request, *args, **kwargs):
        otp_base32 = pyotp.random_base32()
        user = request.user
        if user.otp_enabled:
            return render(request, self.error_template, {'error_message': '2FA already enabled'})

        otp_auth_url = pyotp.totp.TOTP(otp_base32).provisioning_uri(name=user.email.lower(), issuer_name='keyfortress')

        qr = qrcode.make(otp_auth_url)
        buffered = BytesIO()
        qr.save(buffered, format="PNG")
        qr_image_data = buffered.getvalue()
        user.otp_enabled = True
        user.otp_verified = False 
        user.otp_auth_url = otp_auth_url
        user.otp_base32 = otp_base32

        user.user_otp_qrcode.save(f'qr_code_{user.id}.png', ContentFile(qr_image_data))

        user.save()
        print(user.otp_auth_url)

        return render(request, self.template_name, {'user': user})