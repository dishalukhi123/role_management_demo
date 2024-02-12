# decorators.py
from functools import wraps
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect
from django.contrib import messages
from .models import Users

# Role Constants
ADMIN_ROLE_NAME = "ADMIN"
MEMBER_ROLE_NAME = "MEMBER"

def admin_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        user = request.user
        if user.is_superuser or (
            user.roles.filter(role_name=ADMIN_ROLE_NAME).exists() and
            user.roles.filter(role_name=MEMBER_ROLE_NAME).exists()
        ):
            return view_func(request, *args, **kwargs)
        else:
            messages.error(request, "Admin and Member access required.")
            return redirect("base")

    return _wrapped_view

def member_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        user = request.user
        if user.is_authenticated:
            if user.is_superuser or user.roles.filter(role_name=ADMIN_ROLE_NAME).exists():
                return view_func(request, *args, **kwargs)
        return redirect("base")

    return _wrapped_view

def role_required(role_name):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            user = request.user
            if user.is_superuser or user.roles.filter(role_name=role_name).exists():
                return view_func(request, *args, **kwargs)
            else:
                messages.error(request, f"{role_name} access required.")
                return redirect("base")

        return _wrapped_view

    return decorator
