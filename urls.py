from django.urls import include, path
from rest_framework import routers
from rest_framework.urlpatterns import format_suffix_patterns
from .views import (
    get_username,
    set_csrf_cookie,
    get_register_conf,
    WebauthnRegisterBegin,
    WebauthnRegister,
    get_login_conf,
    redeem_login_token,
    WebauthnLoginBegin,
    WebauthnLogin,
    logout,
    AuthenticatorView,
    GroupView,
    UserView,
)


router = routers.SimpleRouter()
router.register("user", UserView, 'user')
router.register("group", GroupView, 'group')
router.register("authenticator", AuthenticatorView, 'authenticator')

urlpatterns = [
    path('register/begin/', WebauthnRegisterBegin.as_view(), name='register-begin'),
    path('register/',       WebauthnRegister.as_view(),      name='register'),
    path('login/token/',    redeem_login_token,              name='login-token'),
    path('login/begin/',    WebauthnLoginBegin.as_view(),    name='login-begin'),
    path('login/',          WebauthnLogin.as_view(),         name='login'),
    path('logout/',         logout,                          name='logout'),

    path("", include(router.urls)),
]

urlpatterns = format_suffix_patterns(urlpatterns)
