from rest_framework.permissions import BasePermission


class IsSuperUser(BasePermission):
    def has_permission(self, request, *args, **kwargs):
        return request.user and request.user.is_superuser


class IsAnonymous(BasePermission):
    def has_permission(self, request, *args, **kwargs):
        return request.user.is_anonymous
