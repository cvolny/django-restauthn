from django.contrib.auth import get_user_model, tokens
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from fido2.utils import websafe_encode, websafe_decode
from fido2.ctap2 import AttestedCredentialData
from hashlib import md5


EXPIRY = 600


def get_user_dict(user):
    return dict(
        id=user.username.encode('utf-8'),
        name=user.username,
        displayName=(user.get_full_name() or user.username)
    )


class Authenticator(models.Model):
    user      = models.ForeignKey(get_user_model(), related_name="authenticators", on_delete=models.CASCADE)
    name      = models.CharField(_('Nickname'), max_length=100)
    created   = models.DateTimeField(_('Created'), auto_now_add=True)
    cred_id   = models.TextField(unique=True)
    cred_data = models.TextField()
    counter   = models.PositiveIntegerField(default=1)

    class Meta:
        verbose_name = _('Authenticator')
        verbose_name_plural = _('Authenticators')
        unique_together = ('user', 'name',)

    def inc_counter(self):
        self.counter += 1
        self.save()
        return self

    @property
    def crid(self):
        return websafe_decode(self.cred_id)

    @property
    def credential(self):
        return AttestedCredentialData(websafe_decode(self.cred_data))

    @credential.setter
    def credential(self, cred):
        self.cred_data = websafe_encode(cred)
        self.cred_id = websafe_encode(cred.credential_id)

    def __str__(self):
        return f'{self.user.username}: {md5(self.crid).hexdigest()} ({self.counter})'


class LoginToken(models.Model):
    token = models.CharField(_('Token'), max_length=64, primary_key=True)
    user = models.ForeignKey(get_user_model(), related_name="tokens", on_delete=models.CASCADE)
    created = models.DateTimeField(_('Created'), auto_now_add=True)
    expires = models.DateTimeField(_('Expires'))

    class Meta:
        verbose_name = _('Token')
        verbose_name_plural = _('Tokens')

    @property
    def expired(self):
        return timezone.now() > self.expires

    def redeem(self):
        if not self.expired:
            self.delete()
            return self.user
        return False

    def generate_token(self):
        return tokens.default_token_generator.make_token(self.user)

    def renew(self):
        self.expires = timezone.now() + timezone.timedelta(minutes=EXPIRY)
        self.redeemed = None

    def save(self, *args, **kwargs):
        if not self.expires:
            self.renew()
        if not self.token:
            self.token = self.generate_token()
        return super(LoginToken, self).save(*args, **kwargs)

    def __str__(self):
        return f'{self.user.username}: {self.created}'