from django.contrib import auth
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.models import Group
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_safe
from fido2.client import ClientData
from fido2.ctap2 import AttestationObject, AuthenticatorData
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity
from logging import getLogger
from rest_framework import permissions
from rest_framework import status
from rest_framework import viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.parsers import JSONParser
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import *
from .parsers import *
from .permissions import *
from .renderers import *
from .serializers import *
from .settings import settings


logger = getLogger(__name__)
RP = PublicKeyCredentialRpEntity(settings.FIDO2.RP_URL, settings.FIDO2.RP_NAME)
SERVER = Fido2Server(RP)


def redact(data, fields=['password'], redacted="_redacted_"):
    return {k: (v if k not in fields else redacted) for k, v in data.items() }


def getuser(user):
    if user.is_authenticated:
        return dict(
            username=user.username,
            full_name=(user.get_full_name() or user.username),
            is_staff=user.is_staff,
            is_authenticated=True)
    return dict(
        username=None,
        full_name='Not logged in',
        is_staff=False,
        is_authenticated=False)


@api_view(['POST'])
@permission_classes([])
def redeem_login_token(request, format=None):
    username = request.data.get('username', None)
    token = request.data.get('token', None)
    logger.warn(f'redeem_login_token({username}, {token})')
    if username and token:
        user = get_user_model().objects.get(username=username)
        if user:
            token = user.tokens.get(pk=token)
            if token.redeem():
                auth.login(request, user)
                return Response(dict(detail="OK"))
            else:
                return Response(dict(detail="Token expired"), status=status.HTTP_401_UNAUTHORIZED)
    return Response(dict(detail="Bad login"), status=status.HTTP_401_UNAUTHORIZED)


@api_view(permissions.SAFE_METHODS)
@permission_classes([])
@ensure_csrf_cookie
def get_username(request, format=None):
    """
    Getter for current username/fullname if authenticated; None if anonymous.
    """
    return Response(dict(details="OK", user=getuser(request.user)))

@api_view(permissions.SAFE_METHODS)
@permission_classes([])
@ensure_csrf_cookie
def set_csrf_cookie(request, format=None):
    """
    Trivial view decorated with @ensure_csrf_cookie.
    """
    return Response(dict(detail="OK"))


@api_view(permissions.SAFE_METHODS)
@permission_classes([])
@ensure_csrf_cookie
def get_login_conf(request, format=None):
    """
    Getter for current authenticate() fields required for login from settings.FIDO2.
    """
    return Response(dict(detail="OK", fields=settings.FIDO2.LOGIN_FIELDS, user=getuser(request.user)))

@api_view(permissions.SAFE_METHODS)
@permission_classes([])
@ensure_csrf_cookie
def get_register_conf(request, format=None):
    """
    Getter for current authenticate() fields required for register from settings.FIDO2.
    """
    return Response(dict(detail="OK", fields=settings.FIDO2.REGISTER_FIELDS, user=getuser(request.user)))



@api_view(permissions.SAFE_METHODS)
def logout(request, format=None):
    """
    Standard logout view.
    """
    auth.logout(request)
    return Response(dict(detail="OK"))

class LoginView(APIView):
    """
    Classic user/pass over post login.

    Note: this isn't registered in urls.py
    """
    def post(self, request, format=None):
        username = request.data.get('username')
        password = request.data.get('password')
        if username and password:
            user = auth.authenticate(username=username, password=password)
            if user:
                auth.login(request, user)
                return Response(dict(detail="OK"))
        return Response(dict(detail="Invalid credentials"), status=status.HTTP_401_UNAUTHORIZED)


class UserView(viewsets.ModelViewSet):
    """
    Super-user only ModelViewSet for auth.get_user_model() model.
    """
    serializer_class = UserSerializer
    permission_classes = (IsSuperUser,)
    queryset = get_user_model().objects.all()

class GroupView(viewsets.ModelViewSet):
    """
    Super-user only ModelViewSet for the auth.Group model.
    """
    serializer_class = GroupSerializer
    permission_classes = (IsSuperUser,)
    queryset = Group.objects.all()

class AuthenticatorView(viewsets.ModelViewSet):
    """
    Super-user only ModelViewSet for the Authenticator model.
    """
    serializer_class = AuthenticatorSerializer
    permission_classes = (IsSuperUser,)
    queryset = Authenticator.objects.all()


class BaseWebauthnView(APIView):
    """
    Base APIView for all Webauthn View Classes.

    Configured for CBOR encoded data, but with BrowseableAPI and JSON support if DEBUG=T.
    """
    renderer_classes = (CborRenderer, CborBrowsableAPIRenderer)
    parser_classes = (CborParser, JSONParser)

class BaseWebauthnLoginView(BaseWebauthnView):
    """
    Base Class for Webauthn Login View Classes.

    Override default permission_classes to be wide open.
    """
    permission_classes = []

class BaseWebauthnRegisterView(BaseWebauthnView):
    """
    Base Authenticator for Webauthn Register View Classes.

    User must be authenticated for these views.
    """
    permission_classes = (permissions.IsAuthenticated,)

class WebauthnRegisterBegin(BaseWebauthnRegisterView):
    """
    Webauthn Register Begin View

    Given the currently logged in user, query their registered authenticators,
        generate a fido2 registration challenge, save state in session.
    """
    def get_userinfo(self, user):
        return dict(
            id=user.username.encode('utf-8'),
            name=user.username,
            displayName=(user.get_full_name() or user.username))

    def post(self, request, format=None):
        logger.info(f'webauthn-register-begin.{format}: {request.data}')
        credentials = [ x.credential for x in request.user.authenticators.all() ]
        userinfo = self.get_userinfo(request.user)
        data, state = SERVER.register_begin(userinfo, credentials,
                        user_verification=settings.FIDO2.USER_VERIFICATION, authenticator_attachment=settings.FIDO2.AUTHENTICATOR_ATTACHMENT)
        request.session[settings.FIDO2.SESSION_STATE_KEY] = state
        return Response(data)

class WebauthnRegister(BaseWebauthnRegisterView):
    """
    Webauthn Register Complete View

    Given the currently logged in user, state from register-begin in session, and the client response,
        complete registration ritual and, if valid, register the new Authenticator.
    """
    def post(self, request, format=None):
        logger.info(f'webauthn-register.{format}: {request.data}')
        clientData = request.data.get("clientDataJSON", None)
        attestationData = request.data.get("attestationObject", None)
        if clientData and attestationData:
            client = ClientData(clientData)
            attestation = AttestationObject(attestationData)
            state = request.session.get(settings.FIDO2.SESSION_STATE_KEY)
            if client and attestation and state:
                try:
                    auth_data = SERVER.register_complete(state, client, attestation)
                    cred_data = auth_data.credential_data
                    authenticator = Authenticator.objects.create(user=request.user, credential=cred_data)
                    logger.info(f'register fido2 for "{request.user.username}": {cred_data.credential_id}')
                    return Response(dict(detail="OK", user=getuser(request.user)))
                except Exception as e:
                    logger.warn(f'Exception webauthn-register.{format} {request.user.username}: {e}')
        return Response(dict(detail="Bad request"), status=status.HTTP_400_BAD_REQUEST)

class WebauthnLoginBegin(BaseWebauthnLoginView):
    """
    Webauthn Login Begin View

    Given an anonymous user, extract authentication data from request, use it to authenticate the user,
        generate a webauthn challenge, store state in session, and return challenge as response.
    """
    def post(self, request, format=None):
        logger.warn(f'webauthn-login-begin.{format}: {request.data.keys()}')
        if request.user.is_authenticated:
            return Response(dict(detail="Already authenticated"), status=status.HTTP_401_UNAUTHORIZED)
        authargs = {k: v for k, v in request.data.items() if k in settings.FIDO2.LOGIN_FIELDS }
        if authargs:
            user = auth.authenticate(request, passwordless=True, **authargs)
            if user:
                credentials = [ x.credential for x in user.authenticators.all() ]
                if credentials:
                    data, state = SERVER.authenticate_begin(credentials, user_verification=settings.FIDO2.USER_VERIFICATION)
                    request.session[settings.FIDO2.SESSION_STATE_KEY] = state
                    return Response(data)
                logger.warn(f'No authenticators registered for login attempt by {user.username}')
                return Response(dict(detail="No Authenticators Registered"), status=status.HTTP_401_UNAUTHORIZED)
            logger.warn(f'Bad authargs {redact(authargs)}')
        else:
            logger.warn(f'Bad payload: {redact(request.data)}')
        return Response(dict(detail="Bad payload"), status=status.HTTP_400_BAD_REQUEST)

class WebauthnLogin(BaseWebauthnLoginView):
    """
    Webauthn Login Complete View

    Given anonymous user, state from login-begin in session, and the client's response, complete the login
        ritual, and if valid, log the user in.
    """
    def post(self, request, format=None):
        logger.info(f'webauthn-login.{format}: {request.data}')
        if request.user.is_authenticated:
            return Response(dict(detail="Already authenticated"), status=status.HTTP_401_UNAUTHORIZED)
        authargs = {k: v for k, v in request.data.items() if k in settings.FIDO2.LOGIN_FIELDS }
        try:
            user = auth.authenticate(request, passwordless=True, **authargs)
        except:
            user = None
        if user:
            state = request.session.get(settings.FIDO2.SESSION_STATE_KEY)
            cred_id = request.data.get('credentialId', None)
            client_json = request.data.get("clientDataJSON", None)
            auth_value = request.data.get("authenticatorData", None)
            signature = request.data.get("signature", None)
            if client_json and auth_value and signature:
                client_data = ClientData(client_json)
                auth_data = AuthenticatorData(auth_value)
                credentials = [ x.credential for x in user.authenticators.all() ]
                if state and credentials and cred_id and client_data and auth_data and signature:
                    try:
                        if SERVER.authenticate_complete(state, credentials, cred_id, client_data, auth_data, signature):
                            auth.login(request, user)
                            return Response(dict(detail="OK", user=getuser(user)))
                    except Exception as e:
                        logger.warn(f'Exception webauthn-login.{format} {authargs}: {e}')
            return Response(dict(detail="Bad request"), status=status.HTTP_400_BAD_REQUEST)
        return Response(dict(detail="Bad username"), status=status.HTTP_401_UNAUTHORIZED)
