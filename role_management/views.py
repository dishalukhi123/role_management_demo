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
from rest_framework import serializers
from django.db.models import Q


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
        try:
            parent_user = Users.objects.get(id=member.parent_id)
            if parent_user:
                member.parent_username = parent_user.username
            else:
                member.parent_username = ""
        except Users.DoesNotExist:
            member.parent_username = ""

# View for adding an admin
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
                    "success" :True,
                    "admin_id": user.id,
                    "created_at": user.formatted_created_at(),
                    "updated_at": user.formatted_updated_at(),
                },
            )

        except Exception as e:
            return sendResponse(400, f"Error: {str(e)}")

# View for adding a member
class AddMemberView(View):
    @method_decorator(login_required(login_url="login"))
    @method_decorator(member_required)
    def get(self, request, admin_id):
        members = Users.objects.filter(parent_id=admin_id).order_by("-id")
        admin_username(members)
        member_count = members.count()

        return render(
            request,
            "add_member.html",
            {
                "admin_id": admin_id,
                "members": members,
                "member_count" :member_count,
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
                    "success" :True,
                    "member_id": user.id,
                    "parent_username": parent_username,
                    "created_at": user.formatted_created_at(),
                    "updated_at": user.formatted_updated_at(),
                },
            )
        except Exception as e:
            return sendResponse(400, f"Error: {str(e)}")
        
    def delete(self, request, member_id):
        print('============',member_id)
        try:
            member = Users.objects.get(id=member_id)
            member.delete()
            return sendResponse(code=200, message="member deleted successfully.")
        except Users.DoesNotExist:
            return sendResponse(code=404, message="member does not exist.")
        except Exception as e:
            return sendResponse(code=400, message=f"Error: {str(e)}")
    
# View for listing admins
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

        search_query = request.GET.get('search')
        if search_query:
            admins = admins.filter(
                Q(username__icontains=search_query) |
                Q(email__icontains=search_query) |
                Q(first_name__icontains=search_query) |
                Q(last_name__icontains=search_query) |
                Q(address__icontains=search_query) |
                Q(gender__icontains=search_query)
            )

        admin_count = admins.count()

        paginator = Paginator(admins, 9)
        page = request.GET.get('page')
        try:
            admins = paginator.page(page)
        except PageNotAnInteger:
            admins = paginator.page(1)
        except EmptyPage:
            admins = paginator.page(paginator.num_pages)

        return render(request, "admins.html", {"admins": admins, "admin_count" : admin_count})


    # def delete(self, request, admin_id):
    #     try:
    #         admin = Users.objects.get(id=admin_id)
    #         admin.delete()
    #         return sendResponse(code=200, message="Admin deleted successfully.")
    #     except Users.DoesNotExist:
    #         return sendResponse(code=404, message="Admin does not exist.")
    #     except Exception as e:
    #         return sendResponse(code=400, message=f"Error: {str(e)}")
        
    def delete(self, request, admin_id):
        try:
            admin = Users.objects.get(id=admin_id)
            admin_members = Users.objects.filter(parent_id=admin_id)
            admin_members.delete()
            admin.delete()
            return sendResponse(code=200, message="Admin and associated members deleted successfully.")
        except Users.DoesNotExist:
            return sendResponse(code=404, message="Admin does not exist.")
        except Exception as e:
            return sendResponse(code=400, message=f"Error: {str(e)}")


# View for editing admin details
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
                    "created_at": user.formatted_created_at(),
                    "updated_at": user.formatted_updated_at(),
                },
            )
        except Users.DoesNotExist:
            return sendResponse(404, "Admin not found")

# View for editing members details
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
                    "parent_username": parent_username,
                    "created_at": user.formatted_created_at(),
                    "updated_at": user.formatted_updated_at(),
                },
            )

        except Users.DoesNotExist:
            return sendResponse(404, "Member not found")

# View for listing members
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

        search_query = request.GET.get('search')
        if search_query:
            members = members.filter(
                Q(username__icontains=search_query) |
                Q(email__icontains=search_query) |
                Q(first_name__icontains=search_query) |
                Q(last_name__icontains=search_query) |
                Q(address__icontains=search_query) |
                Q(gender__icontains=search_query)
            )
        admin_username(members)
        member_count = members.count()

        paginator = Paginator(members, 9)
        page_number = request.GET.get('page')
        try:
            members = paginator.page(page_number)
        except PageNotAnInteger:
            members = paginator.page(1)
        except EmptyPage:
            members = paginator.page(paginator.num_pages)


        return render(
            request,
            "members.html",
            {
                "members": members,
                "current_user": current_user,
                "member_count": member_count,
            },
        )
        
    def delete(self, request, member_id):
        try:
            member = Users.objects.get(id=member_id)
            member.delete()
            return sendResponse(code=200, message="member deleted successfully.")
        except Users.DoesNotExist:
            return sendResponse(code=404, message="member does not exist.")
        except Exception as e:
            return sendResponse(code=400, message=f"Error: {str(e)}")
    
# View for admin members
class AddAdminMembers(View):
    @method_decorator(login_required(login_url="login"))
    @method_decorator(member_required)
    def get(self, request):
        return render(request, "add_member.html")
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

            member_role = Role.objects.get(role_name="MEMBER")
            user.roles.add(member_role)
            parent_user = Users.objects.filter(id=current_user.id).first()
            parent_username = parent_user.username if parent_user else ""

            return sendResponse(
                code=200,
                message="member added successfully.",
                data={
                    "success" :True,
                    "member_id": user.id,
                    "parent_username": parent_username,
                    "created_at": user.formatted_created_at(),
                    "updated_at": user.formatted_updated_at(),
                },
            )

        except Exception as e:
            return sendResponse(400, f"Error: {str(e)}")
        
    def delete(self, request, member_id):
        try:
            member = Users.objects.get(id=member_id)
            member.delete()
            return sendResponse(code=200, message="member deleted successfully.")
        except Users.DoesNotExist:
            return sendResponse(code=404, message="member does not exist.")
        except Exception as e:
            return sendResponse(code=400, message=f"Error: {str(e)}")

# View for handling user logout
class LogoutView(View):
    def get(self, request):
        logout(request)
        return redirect("login")

# View for handling user login
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

# View for home page
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

# View for user registration
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
