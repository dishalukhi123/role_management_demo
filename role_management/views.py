from django.shortcuts import render, redirect
from django.contrib.auth import authenticate
from role_management.models import Users, Role, UsersRoles
from django.views import View
from role_management.utils import sendResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.contrib import messages
from .decorators import admin_required, member_required
from django.utils import timezone
from django.shortcuts import get_object_or_404
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger



def is_superuser(user):
    result = user.roles.filter(role_name="SUPER_ADMIN").exists()
    return result


def user_response(user):
    return sendResponse(
        code=200,
        message="success",
        data={
            "success": True,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "username": user.username,
            "address": user.address,
            "gender": user.gender,
            "created_at": user.created_at,
        },
    )


def admin_username(members):
    for member in members:
        parent_user = Users.objects.filter(id=member.parent_id).first()
        if parent_user:
            member.parent_username = parent_user.username
        else:
            member.parent_username = ""


class AddAdminView(View):
    @method_decorator(login_required(login_url="login"))
    @method_decorator(admin_required)
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
        elif " " in first_name :
            return sendResponse(500, "First name cannot use space")
        elif not first_name.isalpha() :
            return sendResponse(500, "First name can only contain alphabets")
        elif password != confirm_password:
            return sendResponse(500, "Password does not match")

        if Users.objects.filter(username=username).exists():
            return sendResponse(500, "Username already exists")
        elif Users.objects.filter(email=email).exists():
            return sendResponse(500, "Email already exists")

        current_user = request.user
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
                parent_id=current_user.id,
                created_at=timezone.now(),
            )

            admin_role = Role.objects.get(role_name="ADMIN")
            user.roles.add(admin_role)

            return sendResponse(
                code=200,
                message="Admin added successfully.",
                data={
                    "admin_id": user.id,
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "username": user.username,
                    "address": user.address,
                    "gender": user.gender,
                    "created_at": user.formatted_created_at(),
                    "updated_at": user.formatted_updated_at(),
                },
            )

        except Exception as e:
            return sendResponse(400, f"Error: {str(e)}")


class AddMemberView(View):
    @method_decorator(login_required(login_url="login"))
    @method_decorator(member_required)
    def get(self, request, admin_id):
        members = Users.objects.filter(parent_id=admin_id)
        admin_username(members)
        return render(
            request,
            "add_member.html",
            {
                "admin_id": admin_id,
                "members": members,
            },
        )

    def post(self, request, admin_id):
        try:
            email = request.POST.get("email")
            first_name = request.POST.get("first_name")
            last_name = request.POST.get("last_name")
            username = request.POST.get("username")
            password = request.POST.get("password")
            confirm_password = request.POST.get("confirm_password")
            address = request.POST.get("address")
            gender = request.POST.get("gender")

            if " " in username:
                return sendResponse(500, "Username cannot contain spaces")
            elif " " in first_name:
                return sendResponse(500, "First name cannot contain spaces")
            elif not first_name.isalpha():
                return sendResponse(
                    500, "First name can only contain alphabets"
                )
            elif password != confirm_password:
                return sendResponse(500, "Password does not match")
            
            if Users.objects.filter(username=username).exists():
                return sendResponse(500, "Username already exists")
            elif Users.objects.filter(email=email).exists():
                return sendResponse(500, "Email already exists")


            hashed_password = make_password(password)

            user = Users.objects.create(
                email=email,
                first_name=first_name,
                last_name=last_name,
                username=username,
                password=hashed_password,
                address=address,
                gender=gender,
                parent_id=admin_id,
                created_at=timezone.now(),
            )
            member_role = Role.objects.get(role_name="MEMBER")
            user.roles.add(member_role)
            parent_user = Users.objects.filter(id=admin_id).first()
            parent_username = parent_user.username if parent_user else ""

            return sendResponse(
                200,
                "Member added successfully.",
                data={
                    "member_id": user.id,
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "username": user.username,
                    "address": user.address,
                    "gender": user.gender,
                    "parent_username": parent_username,
                    "created_at": user.formatted_created_at(),
                    "updated_at": user.formatted_updated_at(),
                },
            )
        except Exception as e:
            return sendResponse(400, f"Error: {str(e)}")


class AdminView(View):
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

        paginator = Paginator(admins, 8)  
        page_number = request.GET.get('page')
        try:
            admins = paginator.page(page_number)
        except PageNotAnInteger:
            admins = paginator.page(1)
        except EmptyPage:
            admins = paginator.page(paginator.num_pages)

        return render(request, "admins.html", {"admins": admins})


class EditAdminView(View):
    @method_decorator(login_required(login_url="login"))
    @method_decorator(admin_required)
    def get(self, request, admin_id):
        user = Users.objects.get(id=admin_id)
        return user_response(user)

    def post(self, request, admin_id):
        try:
            user = Users.objects.get(id=admin_id)
            data = request.POST
            user.email = data.get("email")
            user.first_name = data.get("first_name")
            user.last_name = data.get("last_name")
            user.username = data.get("username")
            user.address = data.get("address")
            user.gender = data.get("gender")
            user.updated_at = timezone.now()

            if " " in user.username:
                return sendResponse(500, "Username cannot use space")
            elif " " in user.first_name or " " in user.last_name:
                return sendResponse(500, " Name cannot use space")
            elif not user.first_name.isalpha() or not user.last_name.isalpha():
                return sendResponse(500, "You can only use alphabet in name")

            users_list_email = (
                Users.objects.filter(email=user.email).exclude(id=admin_id).exists()
            )
            users_list_username = (
                Users.objects.filter(username=user.username)
                .exclude(id=admin_id)
                .exists()
            )

            if users_list_email:
                return sendResponse(400, "Email address already exists.")
            elif users_list_username:
                return sendResponse(400, "Username already exists.")

            user.save()
            return sendResponse(
                200,
                "Admin updated successfully.",
                data={
                    "admin_id": admin_id,
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "username": user.username,
                    "address": user.address,
                    "gender": user.gender,
                    "created_at": user.formatted_created_at(),
                    "updated_at": user.formatted_updated_at(),
                },
            )
        except Users.DoesNotExist:
            return sendResponse(404, "Admin not found")


class EditMemberView(View):
    @method_decorator(login_required(login_url="login"))
    @method_decorator(member_required)
    def get(self, request, member_id):
        user = Users.objects.get(id=member_id)
        return user_response(user)

    def post(self, request, member_id):
        try:
            user = Users.objects.get(id=member_id)
            data = request.POST
            user.email = data.get("email")
            user.first_name = data.get("first_name")
            user.last_name = data.get("last_name")
            user.username = data.get("username")
            user.address = data.get("address")
            user.gender = data.get("gender")
            user.updated_at = timezone.now()

            if " " in user.username:
                return sendResponse(500, "Username cannot use space")
            elif " " in user.first_name or " " in user.last_name:
                return sendResponse(500, " Name cannot use space")
            elif not user.first_name.isalpha() or not user.last_name.isalpha():
                return sendResponse(500, "You can only use alphabet in name")

            users_list_email = (
                Users.objects.filter(email=user.email).exclude(id=member_id).exists()
            )
            users_list_username = (
                Users.objects.filter(username=user.username)
                .exclude(id=member_id)
                .exists()
            )

            if users_list_email:
                return sendResponse(400, "Email address already exists.")
            elif users_list_username:
                return sendResponse(400, "Username already exists.")


            user.save()
            parent_user = None
            if user.parent_id:
                parent_user = get_object_or_404(Users, id=user.parent_id)
                parent_username = parent_user.username
            else:
                parent_username = None
            return sendResponse(
                200,
                "Member updated successfully.",
                data={
                    "member_id": member_id,
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "username": user.username,
                    "address": user.address,
                    "gender": user.gender,
                    "parent_username": parent_username,
                    "created_at": user.formatted_created_at(),
                    "updated_at": user.formatted_updated_at(),
                },
            )

        except Users.DoesNotExist:
            return sendResponse(404, "Member not found")


class MemberView(View):
    @method_decorator(login_required(login_url="login"))
    @method_decorator(member_required)
    def get(self, request):
        current_user = request.user

        if current_user.is_superuser:
            members = Users.objects.filter(roles__role_name="MEMBER").order_by("-id")
        else:
            members = Users.objects.filter(
                parent_id=current_user.id, roles__role_name="MEMBER"
            ).order_by("-id")

        admin_username(members)

        return render(
            request,
            "members.html",
            {
                "members": members,
                "current_user": current_user,
            },
        )


class LogoutView(View):
    def get(self, request):
        logout(request)
        return redirect("login")


class LoginView(View):
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
            user = Users.objects.get(email=username)
        except Users.DoesNotExist:
            try:
                user = Users.objects.get(username=username)
            except Users.DoesNotExist:
                messages.error(request, "User does not exist.")
                return redirect("login")

        print("User:", user)
        if user and check_password(password, user.password):
            request.session["user_id"] = user.id
            request.session["user_first_name"] = user.first_name
            auth_user = authenticate(request, username=user.username, password=password)
            if auth_user is not None:
                login(request, auth_user)
                next_url = request.GET.get("next")
                if next_url:
                    return redirect(next_url)
                else:
                    return redirect("base")
            else:
                messages.error(request, "User not logged in successfully")
        else:
            messages.error(request, "Incorrect password.")
            return redirect("login")


class HomeView(View):
    @method_decorator(login_required(login_url="login"))
    def get(self, request):
        user_first_name = request.session.get("user_first_name")
        user_member_role = request.user.roles.filter(role_name="MEMBER").exists()

        return render(
            request,
            "index.html",
            {"user_first_name": user_first_name , "user_member_role" : user_member_role},
        )


class SignupView(View):
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
