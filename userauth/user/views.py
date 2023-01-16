import base64

import pyotp
from django.core.mail import EmailMessage

from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect, get_object_or_404
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.views.generic import View
from .forms import LoginForm, RegisterForm, VerifyOTPForm, ResetPasswordForm, ResetEmailForm, UpdateProfileForm
from django.contrib.auth import get_user_model

from .helper import GenerateKey
from .token import account_activation_token

User = get_user_model()


def get_site_url(request):
    return "{}://{}".format(request.scheme, request.get_host())


def send_email(kwargs, template, email, subject):
    message = render_to_string(template, {
        'data': kwargs,
    })
    mail_subject = subject
    to_email = [email]
    sent_mail = EmailMessage(mail_subject, message, to=to_email)
    sent_mail.content_subtype = "html"
    sent_mail.send()


class LoginPageView(View):
    template_name = 'login.html'
    form_class = LoginForm

    def get(self, request):
        form = self.form_class()
        message = ''
        return render(request, self.template_name, context={'form': form, 'message': message})

    def post(self, request):
        form = self.form_class(request.POST)
        if form.is_valid():
            user = authenticate(
                username=form.cleaned_data['username'],
                password=form.cleaned_data['password'],
            )
            if user is not None:
                token = account_activation_token.make_token(user)
                uid_64 = urlsafe_base64_encode(force_bytes(user.email))
                user_token = f'{token}${uid_64}'
                secret = base64.b32encode(user_token.encode())
                otp_data = GenerateKey.get_totp(secret)
                otp = otp_data['OTP']
                data = {'otp': otp}
                subject = 'Login Otp Email'
                send_email(data, 'email_notify.html', user.email, subject)
                login(request, user)
                return render(request, 'verify-login.html', context={'token': secret})

        message = 'Login failed!'
        return render(request, self.template_name, context={'form': form, 'message': message})


class RegisterPageView(View):
    template_name = 'register.html'
    form_class = RegisterForm

    def get(self, request):
        form = self.form_class()
        message = ''
        return render(request, self.template_name, context={'form': form, 'message': message})

    def post(self, request):
        form = self.form_class(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            existing_user = User.objects.filter(email=email)
            if existing_user:
                message = 'Email Already Exists.'
            else:
                user = User.objects.create_user(email=email, password=form.cleaned_data['password'])
                user.is_active = False
                user.save()
                token = account_activation_token.make_token(user)
                uid_64 = urlsafe_base64_encode(force_bytes(user.email))
                user_token = f'{token}${uid_64}'
                secret = base64.b32encode(user_token.encode())
                otp_data = GenerateKey.get_totp(secret)
                otp = otp_data['OTP']
                data = {'otp': otp}
                subject = 'Registration Email'
                send_email(data, 'email_notify.html', form.cleaned_data['email'], subject)
                login(request, user)
                return render(request, 'varify-register.html', context={'token': secret})
        else:
            message = 'Register Failed!'
        return render(request, self.template_name, context={'form': form, 'message': message})


class VerifyOTPView(View):
    form_class = VerifyOTPForm
    template_name = 'varify-register.html'

    def get(self, request):
        form = self.form_class()
        message = ''
        return render(request, self.template_name, context={'form': form, 'message': message})

    def post(self, request):
        form = self.form_class(request.POST)
        if form.is_valid():
            otp = form.cleaned_data['otp']
            token = form.cleaned_data['token'].split('b')[1].split("\'")[1]
            data = GenerateKey.verify_totp(token, otp)
            if data:
                user = GenerateKey.get_user(token)
                if user:
                    user.is_active = True
                    user.save()
                    subject = 'Welcome Email'
                    send_email(user, 'email_notify.html', user.email, subject)
                    return redirect("login")
                message = 'Otp Verification Failed'
            else:
                message = 'OTP Expired'
        else:
            message = 'Register Failed!'
        return render(request, self.template_name, context={'form': form, 'message': message})


class VerifyOTPLoginView(View):
    form_class = VerifyOTPForm
    template_name = 'verify-login.html'

    def get(self, request):
        form = self.form_class()
        message = ''
        return render(request, self.template_name, context={'form': form, 'message': message})

    def post(self, request):
        form = self.form_class(request.POST)
        if form.is_valid():
            otp = form.cleaned_data['otp']
            token = form.cleaned_data['token'].split('b')[1].split("\'")[1]
            data = GenerateKey.verify_totp(token, otp)
            if data:
                user = GenerateKey.get_user(token)
                if user:
                    return redirect("profile")
                message = 'Otp Verification Failed'
            else:
                message = 'OTP Expired'
        else:
            message = 'Register Failed!'
        return render(request, self.template_name, context={'form': form, 'message': message})


class ForgetEmailView(View):
    form_class = ResetEmailForm
    template_name = 'forgot-password.html'

    def get(self, request):
        form = self.form_class()
        message = ''
        return render(request, self.template_name, context={'form': form, 'message': message})

    def post(self, request):
        form = self.form_class(request.POST)
        if form.is_valid():
            user = User.objects.filter(email=form.cleaned_data['email'])
            if user:
                return render(request, 'reset-password.html', context={'email': form.cleaned_data['email']})
            else:
                message = "User Doesn't Exist"
        else:
            message = 'Verification Failed!'
        return render(request, self.template_name, context={'form': form, 'message': message})


class ResetPasswordView(View):
    form_class = ResetPasswordForm
    template_name = 'reset-password.html'

    def get(self, request):
        form = self.form_class()
        message = ''
        return render(request, self.template_name, context={'form': form, 'message': message})

    def post(self, request):
        form = self.form_class(request.POST)
        if form.is_valid():
            if form.cleaned_data['password'] != form.cleaned_data['confirm_password']:
                message = 'Password Did Not match'
            else:
                user = User.objects.filter(email=form.data['email']).first()
                if user:
                    user.set_password(form.cleaned_data['password'])
                    user.save()
                    login(request, user)
                    return redirect("index")
                else:
                    message = 'User Not Found'
        else:
            message = 'Register Failed!'
        return render(request, self.template_name, context={'form': form, 'message': message})


class ProfileView(View):
    form_class = ResetPasswordForm
    template_name = 'profile.html'

    def get(self, request):
        form = self.form_class()
        message = ''
        user = self.request.user
        return render(request, self.template_name, context={'form': form, 'message': message, 'user': user})


class UpdateProfileView(View):
    form_class = UpdateProfileForm
    template_name = 'edit-profile.html'

    def get(self, request):
        form = self.form_class()
        message = ''
        user = self.request.user
        return render(request, self.template_name, context={'form': form, 'message': message, 'user': user})

    def post(self, request):
        form = self.form_class(request.POST)
        if form.is_valid():
            user = self.request.user
            if form.cleaned_data.get('first_name'):
                user.first_name = form.cleaned_data.get('first_name')
            if form.cleaned_data.get('last_name'):
                user.last_name = form.cleaned_data.get('last_name')
            if request.FILES:
                user.profile = request.FILES['profile']
            user.save()
            message = 'Profile Updated'
        else:
            message = 'Profile Update Failed!'
        return render(request, self.template_name, context={'form': form, 'message': message})


class DeleteUserView(View):
    def get(self, request):
        if self.request.user.is_anonymous:
            message = 'No Login User Found'
        else:
            pk = self.request.user.id
            data = get_object_or_404(User, id=pk)
            data.delete()
            return redirect("index")
        return render(request, 'index.html', context={'message': message})


class ChangePasswordView(View):
    form_class = ResetPasswordForm
    template_name = 'change-password.html'

    def get(self, request):
        form = self.form_class()
        message = ''
        return render(request, self.template_name, context={'form': form, 'message': message})

    def post(self, request):
        form = self.form_class(request.POST)
        if form.is_valid():
            if form.cleaned_data['password'] != form.cleaned_data['confirm_password']:
                message = 'Password Did Not match'
            else:
                user = self.request.user
                if user and user.is_authenticated:
                    user.set_password(form.cleaned_data['password'])
                    user.save()
                    login(request, user)
                    return redirect("index")
                else:
                    message = 'You are Not Login'
        else:
            message = 'Register Failed!'
        return render(request, self.template_name, context={'form': form, 'message': message})
