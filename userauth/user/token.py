from django.contrib.auth.tokens import PasswordResetTokenGenerator


class AccountActivationTokenGenerator(PasswordResetTokenGenerator):
    def make_token(self, user):
        return self._make_token_with_timestamp(user, self._num_seconds(self._now()))


account_activation_token = AccountActivationTokenGenerator()
