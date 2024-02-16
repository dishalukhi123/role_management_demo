from django.urls import path
from .views import HomeView, SignupView, LoginView, LogoutView, AdminView, MemberView, EditAdminView, AddAdminView , AddMemberView , EditMemberView 
from django.contrib.auth.decorators import login_required

urlpatterns = [
    path('', login_required(HomeView.as_view()), name="base"),
    path('admins/', AdminView.as_view(), name="admins"),
    path('admins/<int:admin_id>', EditAdminView.as_view(), name='edit_admin'),
    path('admins/add', AddAdminView.as_view(), name='add_admin'),
    path('admins/<int:admin_id>/members', AddMemberView.as_view(), name='add_member'),
    path('members/add/<int:admin_id>', AddMemberView.as_view(), name='add_member'),
    path('members/<int:member_id>', EditMemberView.as_view(), name='edit_member'),
    path('members/', MemberView.as_view(), name="members"),
    path('login/', LoginView.as_view(), name="login"),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('signup/', SignupView.as_view(), name="signup"),
]
