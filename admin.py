from django.contrib import admin
from .models import *


class AuthenticatorAdmin(admin.ModelAdmin):
    pass

admin.site.register(Authenticator, AuthenticatorAdmin)
