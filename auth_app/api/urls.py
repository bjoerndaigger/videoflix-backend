from django.urls import path
from .views import RegisterView, ActivateAccountView, LoginView,CookieRefreshView, LogoutView, RequestPasswordResetView, PasswordConfirmView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('activate/<uidb64>/<token>/', ActivateAccountView.as_view(), name='activate'),  
    path('login/', LoginView.as_view(), name='login'),  
    path('token/refresh/', CookieRefreshView.as_view(), name='token_refresh'), 
    path('logout/', LogoutView.as_view(), name='logout'), 
    path('password_reset/', RequestPasswordResetView.as_view(), name='password_reset'), 
    path('password_confirm/<uidb64>/<token>/', PasswordConfirmView.as_view(), name='password_confirm'), 
]
