import base64
import datetime

import pyotp
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.crypto import salted_hmac
from django.utils.encoding import force_text
from django.utils.http import int_to_base36, urlsafe_base64_decode
from django.contrib.auth import get_user_model

User = get_user_model()


class OTPTokenGenerator(PasswordResetTokenGenerator):
    def _make_token_with_timestamp(self, user, timestamp, legacy=False):
        # timestamp is number of seconds since 2001-1-1. Converted to base 36,
        # this gives us a 6 digit string until about 2069.
        # ts_b36 = int_to_base36(timestamp)
        ts_b36 = int_to_base36(timestamp)
        hash_string = salted_hmac(
            self.key_salt,
            self._make_hash_value(user, timestamp),
            secret=self.secret,
        ).hexdigest()[::2]  # Limit to 20 characters to shorten the URL.
        return "%s-%s" % (ts_b36, hash_string)
        # hash_string = salted_hmac(
        #     self.key_salt,
        #     self._make_hash_value(user),
        #     secret=self.secret,
        #     # RemovedInDjango40Warning: when the deprecation ends, remove the
        #     # legacy argument and replace with:
        #     #   algorithm=self.algorithm,
        #     # algorithm='sha1' if legacy else self.algorithm,
        # ).hexdigest()[
        #     ::2
        # ]  # Limit to shorten the URL.
        # return '%s' % (hash_string)

    def _make_hash_value(self, user, timestamp):
        """
        Hash the user's primary key and some user state that's sure to change
        after a password reset to produce a token that invalidated when it's
        used:
        1. The password field will change upon a password reset (even if the
           same password is chosen, due to password salting).
        2. The last_login field will usually be updated very shortly after
           a password reset.
        Failing those things, settings.PASSWORD_RESET_TIMEOUT eventually
        invalidates the token.

        Running this data through salted_hmac() prevents password cracking
        attempts using the reset token, provided the secret isn't compromised.
        """
        # Truncate microseconds so that tokens are consistent even if the
        # database doesn't support microseconds.
        current_timestamp = datetime.datetime.now()
        # login_timestamp = '' if user.last_login is None else user.last_login.replace(microsecond=0, tzinfo=None)
        return str(user.pk) + user.password + str(current_timestamp) + str(timestamp)


otp_token = OTPTokenGenerator()


class GenerateKey:
    @staticmethod
    def get_totp(token):
        print(token, "generate")
        totp = pyotp.TOTP(token, interval=300)  # 5 minute interval
        OTP = totp.now()
        return {'token': token, 'OTP': OTP}

    @staticmethod
    def verify_totp(token, otp, valid_window=1):
        print(token, "verify")
        # secret = base64.b32encode(token)
        totp = pyotp.TOTP(token, interval=300)  # 5 minute interval
        return totp.verify(otp, valid_window=valid_window)

    @staticmethod
    def get_user(secret):
        user_token = str(base64.b32decode(secret))
        token = user_token.split('$')[0][2:]
        uid = user_token.split('$')[1][:-1]
        uid = force_text(urlsafe_base64_decode(uid))
        user = User.objects.get(email=uid)
        return user
