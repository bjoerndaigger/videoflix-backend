from django.urls import path
from .views import RegisterView, ActivateAccountView, LoginView,CookieRefreshView, LogoutView, RequestPasswordResetView, PasswordConfirmView, TestProtectedView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),  # User registration endpoint
    path('activate/<uidb64>/<token>/', ActivateAccountView.as_view(), name='activate'),  # Account activation
    path('login/', LoginView.as_view(), name='login'),  # JWT login endpoint
    path('token/refresh/', CookieRefreshView.as_view(), name='token_refresh'), #JWT token refresh
    path('logout/', LogoutView.as_view(), name='logout'), # Logout and blacklist refresh token
    path('password_reset/', RequestPasswordResetView.as_view(), name='password_reset'), # Send email for password reset
    path('password_confirm/<uidb64>/<token>/', PasswordConfirmView.as_view(), name='password_confirm'),  # Confirm new password
    path('test/', TestProtectedView.as_view(), name='test') # Protected test endpoint to verify JWT authentication
]
