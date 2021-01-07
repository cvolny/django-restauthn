from django.contrib.auth import backends, get_user_model


class PasswordlessBackend(backends.ModelBackend):
    def authenticate(self, request, passwordless=False, username=None, **kwargs):
        if passwordless:
            try:
                return get_user_model().objects.get(username=username)
            except:
                pass
