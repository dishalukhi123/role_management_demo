from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate
from role_management.models import users, Role, UsersRoles
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


class add_adminView(View):
    def get(self ,request):
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
        admin_id = request.POST.get("admin_id")

        print("Received data:")
        print("Email:", email)
        print("First Name:", first_name)
        print("Last Name:", last_name)
        print("Username:", username)
        print("Password:", password)
        print("Confirm Password:", confirm_password)
        print("Address:", address)
        print("Gender:", gender)
        print("Admin ID:", admin_id)

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
            users_list = users.objects.filter(email=email).exclude(id=admin_id)
            print(users_list.query)
            if users_list.exists():
                return sendResponse(400, "Email address already exists.")
            elif users_list.exists():
                return sendResponse(400, "Username  already exists.")

            print(
                "===id,email,username,email,firstname,lastname======",
                email,
                first_name,
                last_name,
            )
            admin_user = users.objects.create(
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
            admins = users.objects.filter(roles__role_name="ADMIN").order_by("-id")
        else:
            admins = users.objects.filter(
                parent_id=current_user.id, roles__role_name="ADMIN"
            ).order_by("-id")

        return render(request, "admins.html", {"admins": admins})

  


class edit_adminView(View):
    def get(self, request,admin_id):
        admin_id = request.GET.get("admin_id")
        if admin_id:
            admin = users.objects.filter(id=admin_id).first()
            if admin:
                return render(request, "admin_edit.html", {"admin": admin})
            else:
                messages.error(request, "Admin not found.")
        else:
            messages.error(request, "Admin ID not provided.")
        return render(request, "admins.html")

    def post(self, request):
        admin_id = request.POST.get("admin_id")
        email = request.POST.get("email")
        first_name = request.POST.get("first_name")
        last_name = request.POST.get("last_name")
        username = request.POST.get("username")
        address = request.POST.get("address")
        gender = request.POST.get("gender")

        print("Received data:")
        print("Email:", email)
        print("First Name:", first_name)
        print("Last Name:", last_name)
        print("Username:", username)
        print("Address:", address)
        print("Gender:", gender)
        print("Admin ID:", admin_id)

        if " " in username:
            return sendResponse(500, "Username cannot use space")
        elif " " in first_name:
            return sendResponse(500, "First Name cannot use space")
        elif not first_name.isalpha():
            return sendResponse(500, "You can only use alphabet in first name")

        current_user = request.user
        try:
            users_list = users.objects.filter(email=email).exclude(id=admin_id)
            print(users_list.query)
            if users_list.exists():
                return sendResponse(400, "Email address already exists.")
            elif users_list.exists():
                return sendResponse(400, "Username  already exists.")
            if admin_id:
                admin_user = users.objects.get(id=admin_id)
                admin_user.email = email
                admin_user.first_name = first_name
                admin_user.last_name = last_name
                admin_user.username = username
                admin_user.address = address
                admin_user.gender = gender
                admin_user.save()
                print('====admin___id=====',admin_id)
                messages.success(request, "Admin updated successfully.")
                return sendResponse(200, "Admin updated successfully.")
            else:
                return sendResponse(400, "Admin ID is required for editing.")
        except users.DoesNotExist:
            return sendResponse(400, "Admin does not exist.")


class memberView(View):
    @method_decorator(login_required(login_url="login"))
    @method_decorator(member_required)
    def get(self, request):
        current_user = request.user

        if current_user.is_superuser:
            members = users.objects.filter(roles__role_name="MEMBER")
        else:
            members = users.objects.filter(parent_id=current_user.id)

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
                user = users.objects.get(email=username)
            else:
                user = users.objects.get(username=username)
        except users.DoesNotExist:
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

            user = users.objects.create(
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
