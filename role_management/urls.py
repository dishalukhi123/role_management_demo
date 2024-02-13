from django.urls import path
from .views import HomeView, SignupView, LoginView, LogoutView, AdminView, MemberView, EditAdminView, AddManageView
from django.contrib.auth.decorators import login_required

urlpatterns = [
    path('', login_required(HomeView.as_view()), name="base"),
    path('admins/', AdminView.as_view(), name="admins"),
    path('admins/<int:admin_id>', EditAdminView.as_view(), name='edit_admin'),
    path('admins/add', AddManageView.as_view(), name='add_admin'),  
    path('members/', MemberView.as_view(), name="members"),
    path('login/', LoginView.as_view(), name="login"),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('signup/', SignupView.as_view(), name="signup"),
]
