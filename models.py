from django.contrib.auth import get_user_model
from django.db import models
from django.utils.translation import gettext_lazy as _
from fido2.utils import websafe_encode, websafe_decode
from fido2.ctap2 import AttestedCredentialData
from hashlib import md5


def get_user_dict(user):
    return dict(
        id=user.username.encode('utf-8'),
        name=user.username,
        displayName=(user.get_full_name() or user.username)
    )


class Authenticator(models.Model):
    user      = models.ForeignKey(get_user_model(), related_name="authenticators", on_delete=models.CASCADE)
    created   = models.DateTimeField(_('Created'), auto_now_add=True)
    cred_id   = models.TextField(unique=True)
    cred_data = models.TextField()
    counter   = models.PositiveIntegerField(default=1)

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
