from django.contrib import admin
from .models import *


class AuthenticatorAdmin(admin.ModelAdmin):
    pass

class TokenAdmin(admin.ModelAdmin):
    pass

admin.site.register(Authenticator, AuthenticatorAdmin)
admin.site.register(LoginToken, TokenAdmin)
