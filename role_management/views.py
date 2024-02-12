from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate
from role_management.models import Users, Role, UsersRoles
from django.views import View
from role_management.utils import sendResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.contrib import messages
from django.contrib.auth.views import LoginView
from .decorators import admin_required, member_required
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone


def is_superuser(user):
    result = user.roles.filter(role_name="SUPER_ADMIN").exists()
    return result


class addAdminView(View):
    def get(self, request):
        return render(request, "admins.html")

    def post(self, request):
        email = request.POST.get("email")
        first_name = request.POST.get("first_name")
        last_name = request.POST.get("last_name")
        username = request.POST.get("username")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")
        address = request.POST.get("address")
        gender = request.POST.get("gender")

        if " " in username:
            return sendResponse(500, "Username cannot use space")
        elif " " in first_name:
            return sendResponse(500, "First Name cannot use space")
        elif not first_name.isalpha():
            return sendResponse(500, "You can only use alphabet in first name")
        elif password != confirm_password:
            return sendResponse(500, "Password does not match")

        current_user = request.user
        try:
            hashed_password = make_password(password)

            admin_user = Users.objects.create(
                email=email,
                first_name=first_name,
                last_name=last_name,
                username=username,
                password=hashed_password,
                address=address,
                gender=gender,
                parent_id=current_user.id,
                created_at=timezone.now(),
            )
            admin_role = Role.objects.get(role_name="ADMIN")
            admin_user.roles.add(admin_role)
            messages.success(request, "Admin added successfully.")
            return sendResponse(200, "Admin added successfully.")
        except Exception as e:
            return sendResponse(400, f"Error: {str(e)}")


class adminView(View):
    @method_decorator(login_required(login_url="login"))
    @method_decorator(admin_required)
    def get(self, request):
        current_user = request.user
        if current_user.is_superuser:
            admins = Users.objects.filter(roles__role_name="ADMIN").order_by("-id")
        else:
            admins = Users.objects.filter(
                parent_id=current_user.id, roles__role_name="ADMIN"
            ).order_by("-id")

        return render(request, "admins.html", {"admins": admins})





class editAdminView(View):
    def get(self, request, admin_id):
        print('===admin_id====',admin_id)
        users_list = Users.objects.get(id=admin_id)
        return sendResponse(code= 200,
           message= 'success',
           data= {
               
                'success': True,
                "email": users_list.email,
                "first_name": users_list.first_name,
                "last_name": users_list.last_name,
                "username": users_list.username,
                "address" : users_list.address,
                "gender" : users_list.gender,
            },
        )
    def post(self, request, admin_id):
        try:
            user = Users.objects.get(id=admin_id)
            data = request.POST
            user.first_name = data.get('first_name')
            user.last_name = data.get('last_name')
            user.username = data.get('username')
            user.address = data.get('address')
            user.gender = data.get('gender')
            user.email = data.get('email')

            users_list_email = Users.objects.filter(email=user.email).exclude(id=admin_id)
            users_list_username = Users.objects.filter(username=user.username).exclude(id=admin_id)

            if users_list_email.exists():
                return sendResponse(400, "Email address already exists.")
            elif users_list_username.exists():
                return sendResponse(400, "Username already exists.")


            user.save()
            return sendResponse(200,'Admin updated successfully.')
        except Users.DoesNotExist:
            return sendResponse(404, 'Admin not found')



class memberView(View):
    @method_decorator(login_required(login_url="login"))
    @method_decorator(member_required)
    def get(self, request):
        current_user = request.user

        if current_user.is_superuser:
            members = Users.objects.filter(roles__role_name="MEMBER")
        else:
            members = Users.objects.filter(parent_id=current_user.id)

        return render(
            request,
            "members.html",
            {
                "members": members,
                "current_user": current_user,
            },
        )


class logoutView(View):
    def get(self, request):
        logout(request)
        return redirect("login")


class loginView(View):
    def get(self, request):
        if request.user.is_authenticated:
            return redirect("base")
        else:
            return render(request, "login.html", {})

    def post(self, request):
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = None
        try:
            if "@" in username:
                user = Users.objects.get(email=username)
            else:
                user = Users.objects.get(username=username)
        except Users.DoesNotExist:
            messages.error(request, "User does not exist.")
        print("User:", user)  # Print the user object
        if user and check_password(password, user.password):
            request.session["user_id"] = user.id
            request.session["user_first_name"] = user.first_name
            auth_user = authenticate(request, username=username, password=password)
            if auth_user is not None:
                login(request, auth_user)
                next_url = request.GET.get("next")
                if next_url:
                    return redirect(next_url)
                else:
                    return redirect("base")
            else:
                return sendResponse(500, "User not login successfully")
        else:
            return sendResponse(500, "Incorrect username or password.")


class homeView(View):
    @method_decorator(login_required(login_url="login"))
    def get(self, request):
        user_first_name = request.session.get("user_first_name")
        return render(
            request,
            "base.html",
            {"user_first_name": user_first_name},
        )


class signupView(View):
    def get(self, request):
        return render(request, "signup.html", {})

    def post(self, request):
        email = request.POST.get("email")
        first_name = request.POST.get("first_name")
        last_name = request.POST.get("last_name")
        username = request.POST.get("username")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")
        address = request.POST.get("address")
        gender = request.POST.get("gender")

        if " " in username:
            return sendResponse(500, "Username cannot use space")
        elif " " in first_name:
            return sendResponse(500, "First Name cannot use space")
        elif not first_name.isalpha():
            return sendResponse(500, "You can only use alphabet in first name")
        elif password != confirm_password:
            return sendResponse(500, "Password does not match")

        try:
            hashed_password = make_password(password)

            user = Users.objects.create(
                email=email,
                first_name=first_name,
                last_name=last_name,
                username=username,
                password=hashed_password,
                address=address,
                gender=gender,
            )
            return sendResponse(200, "User registration successfully.")
        except Exception as e:
            return sendResponse(400, f"Error: {str(e)}")
