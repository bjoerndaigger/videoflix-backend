from django.urls import path
from .views import RegisterView, ActivateAccountView, LoginView, LogoutView, TestProtectedView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),  # User registration endpoint
    path('activate/<uidb64>/<token>/', ActivateAccountView.as_view(), name='activate'),  # Account activation
    path('login/', LoginView.as_view(), name='login'),  # JWT login endpoint
    path('logout/', LogoutView.as_view(), name='logout'), # Logout and blacklist refresh token
    path('test/', TestProtectedView.as_view(), name='test') # Protected test endpoint to verify JWT authentication
]
