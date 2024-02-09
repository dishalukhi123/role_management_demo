from django.contrib import admin
from .models import users, Role, UsersRoles

admin.site.register(users)
admin.site.register(Role)
admin.site.register(UsersRoles)