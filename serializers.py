from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from rest_framework import serializers
from .models import *


class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ('id', 'username', 'email', 'last_login', 'date_joined', 'groups', 'authenticators')

class GroupSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Group
        fields = ('id', 'name', 'user_set')

class AuthenticatorSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Authenticator
        fields = ('id', 'user', 'cred_id', 'created', 'counter')
