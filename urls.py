from django.urls import include, path
from rest_framework import routers
from rest_framework.urlpatterns import format_suffix_patterns
from .views import *


router = routers.SimpleRouter()
router.register("user", UserView, 'user')
router.register("group", GroupView, 'group')
router.register("authenticator", AuthenticatorView, 'authenticator')

urlpatterns = [
    path('self/',           get_username,                    name='self'),
    path('csrf/',           set_csrf_cookie,                 name='csrf'),
    path('register/conf/',  get_register_conf,               name='register-conf'),
    path('register/begin/', WebauthnRegisterBegin.as_view(), name='register-begin'),
    path('register/',       WebauthnRegister.as_view(),      name='register'),
    path('login/conf/',     get_login_conf,                  name='login-conf'),
    path('login/begin/',    WebauthnLoginBegin.as_view(),    name='login-begin'),
    path('login/',          WebauthnLogin.as_view(),         name='login'),
    path('logout/',         logout,                          name='logout'),

    path("", include(router.urls)),
]

urlpatterns = format_suffix_patterns(urlpatterns)
