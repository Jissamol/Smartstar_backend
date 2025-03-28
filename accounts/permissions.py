from rest_framework.permissions import BasePermission

class IsAdminUser(BasePermission):
    """Allows access only to Admin users."""
    def has_permission(self, request, view):
        return bool(
            request.user and 
            request.user.is_authenticated and 
            (request.user.is_superuser or request.user.role == "admin")
        )

class IsTeacher(BasePermission):
    """Allows access only to Teachers."""
    def has_permission(self, request, view):
        return bool(
            request.user and 
            request.user.is_authenticated and 
            request.user.role == "teacher"
        )

class IsStudent(BasePermission):
    """Allows access only to Students."""
    def has_permission(self, request, view):
        return bool(
            request.user and 
            request.user.is_authenticated and 
            request.user.role == "student"
        )
