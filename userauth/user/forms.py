# authentication/forms.py
from django import forms
from django.contrib.auth import get_user_model

User = get_user_model()


class LoginForm(forms.Form):
    username = forms.CharField(max_length=63)
    password = forms.CharField(max_length=63, widget=forms.PasswordInput)


class RegisterForm(forms.Form):
    email = forms.CharField(max_length=63)
    password = forms.CharField(max_length=63, widget=forms.PasswordInput)


class VerifyOTPForm(forms.Form):
    token = forms.CharField(max_length=255)
    otp = forms.CharField(max_length=6)


class ResetEmailForm(forms.Form):
    email = forms.CharField(max_length=63)


class ResetPasswordForm(forms.Form):
    password = forms.CharField(max_length=63, widget=forms.PasswordInput)
    confirm_password = forms.CharField(max_length=63, widget=forms.PasswordInput)


class UpdateProfileForm(forms.Form):
    # email = forms.CharField(max_length=63, required=False)
    first_name = forms.CharField(max_length=63, required=False)
    last_name = forms.CharField(max_length=63, required=False)
    profile = forms.ImageField(required=False)
    # password = forms.CharField(max_length=63, widget=forms.PasswordInput)
