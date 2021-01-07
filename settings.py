from django.conf import settings
from django.utils.translation import gettext_lazy as _
from types import SimpleNamespace


USERNAME_FIELD = {
    'type': 'text',
    'placeholder': _('username'),
    'label': _('Username:'),
    'tooltip': _('Enter your username')
}

PASSWORD_FIELD = {
    'type': 'password',
    'placeholder': '****************',
    'label': _('Password:'),
    'tooltip': _('Enter your password')
}

TOKEN_FIELD = {
    'type': 'password',
    'placeholder': '******',
    'label': _('Token:'),
    'tooltip': _('Enter MFA Token')
}

DEFAULTS = {
    'RP_URL':                   'localhost',
    'RP_NAME':                  'localhost',
    'USER_VERIFICATION':        'preferred',
    'AUTHENTICATOR_ATTACHMENT': None,
    'SESSION_STATE_KEY':        'fido2_state',
    'LOGIN_FIELDS': {
        'username': USERNAME_FIELD,
        'password': PASSWORD_FIELD,
    },
    'REGISTER_FIELDS': {
    },
}

settings.FIDO2 = SimpleNamespace(**getattr(settings, 'FIDO2', {}))

for key in DEFAULTS.keys():
    setattr(settings.FIDO2, key, getattr(settings.FIDO2, key, DEFAULTS[key]))
