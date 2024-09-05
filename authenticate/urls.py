from django.urls import path, include
from . import views
from django.contrib.auth import views as auth_views
# from django.conf.urls.i18n import i18n_patterns


urlpatterns = [
    path('', views.home, name='home'),
    # path('api/v1/', views.HomePage.as_view(), name='home'),
#     path('api/v1/unauthenticated/', views.HomePage.as_view(), name='home'),
#     path('api/v1/authenticated/', views.HomePage.as_view(), name='home'),
    path('logout/', views.logout_user, name='logout'),
#     path('register/', views.register_user, name='register'),
    path('register/', views.SignUp.as_view(), name='register'),
    path('edit_profile/', views.edit_profile, name='edit_profile'),
    path('change_password/', views.change_password, name='change_password'),
#     path('login_keycloak/', views.login_keycloak, name='login_keycloak'),
    path('login_keycloak/', views.Signin.as_view(), name='login_keycloak'),
#     path('keycloak-callback/', views.keycloak_callback, name='keycloak_callback'),
    path('keycloak-callback/', views.KeycloakCallback.as_view(), name='keycloak_callback'),

    path('password_reset/', auth_views.PasswordResetView.as_view(),
         name='password_reset'),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(),
         name='password_reset_done'),
    path('password_reset/confirm/<uidb64>/<token>/',
         auth_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('password_reset/complete/', auth_views.PasswordResetCompleteView.as_view(),
         name='password_reset_complete'),

]
