from django.contrib import admin
from .models import Users, Role, UsersRoles

admin.site.register(Users)
admin.site.register(Role)
admin.site.register(UsersRoles)