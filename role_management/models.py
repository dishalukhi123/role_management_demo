from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone



class Role(models.Model):
    role_name = models.CharField(max_length=20)

    class Meta:
        db_table = 'Role'

class users(AbstractUser):
    GENDER_CHOICES = (
        ('Male', 'Male'),
        ('Female', 'Female'),
    )

    address = models.TextField(blank=False, null=False)
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES)
    roles = models.ManyToManyField(Role, through='UsersRoles', blank=True)
    parent_id = models.IntegerField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)


    def formatted_created_at(self):
        return self.created_at.strftime("%I:%M %p %A, %b %d, %Y")

    class Meta:
        db_table = 'users'

class UsersRoles(models.Model):
    user = models.ForeignKey(users, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)

    class Meta:
        db_table = 'users_roles'





            