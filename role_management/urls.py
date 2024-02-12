from django.urls import path
from .views import homeView, signupView, loginView, logoutView, adminView, memberView, editAdminView, addAdminView
from django.contrib.auth.decorators import login_required

urlpatterns = [
    path('', login_required(homeView.as_view()), name="base"),
    path('admins/', adminView.as_view(), name="admins"),
    path('admins/<admin_id>', editAdminView.as_view(), name='edit_admin'),
    path('addadmins/', addAdminView.as_view(), name='add_admin'),  
    path('members/', memberView.as_view(), name="members"),
    path('login/', loginView.as_view(), name="login"),
    path('logout/', logoutView.as_view(), name='logout'),
    path('signup/', signupView.as_view(), name="signup"),
]
