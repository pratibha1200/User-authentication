from django.urls import path
from .views import LoginPageView, RegisterPageView, ResetPasswordView, VerifyOTPView, VerifyOTPLoginView, \
    ForgetEmailView, ProfileView, UpdateProfileView, DeleteUserView, ChangePasswordView, LogoutView

urlpatterns = [
    path("login/", LoginPageView.as_view(), name="login"),
    path("register/", RegisterPageView.as_view(), name="register"),
    path("reset-password/", ResetPasswordView.as_view(), name="reset_password"),
    path("verify/", VerifyOTPView.as_view(), name="verify"),
    path("verify-login/", VerifyOTPLoginView.as_view(), name="verify_login"),
    path("forgot-email/", ForgetEmailView.as_view(), name="forgot_email"),
    path("profile/", ProfileView.as_view(), name="profile"),
    path("edit-profile/", UpdateProfileView.as_view(), name="edit_profile"),
    path("delete-user/", DeleteUserView.as_view(), name="delete"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("change-password/", ChangePasswordView.as_view(), name="change_password"),
]
