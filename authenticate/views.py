from django.shortcuts import render, redirect
from django.contrib.auth import login, update_session_auth_hash
from django.contrib import messages
from .forms import SignUpForm, EditProfileForm, ChangePasswordForm
from .utils import keycloak_openid, keycloak_admin, KeycloakAuthenticationBackend
from rest_framework import generics
from django.utils.translation import gettext_lazy as _

def logout_user(request):

    if request.user.is_authenticated:
        keycloak_openid.logout(request.session['refresh_token'])
        request.session.clear()
        messages.success(request, _("Logged out successfully"))
    return redirect('home')

def edit_profile(request):
    if request.method == 'POST':
        form = EditProfileForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, _("Profile Updated Successfully"))
            return redirect('home')
    else:
        form = EditProfileForm(instance=request.user)
    context = {
        'form': form,
    }
    return render(request, 'authenticate/edit_profile.html', context)


def change_password(request):
    if request.method == 'POST':
        form = ChangePasswordForm(data=request.POST, user=request.user)
        if form.is_valid():
            response = keycloak_admin.set_user_password(user_id="user-id-keycloak", password="secret", temporary=True)

            form.save()
            update_session_auth_hash(request, form.user)
            messages.success(request, "Password Changed Successfully")
            return redirect('home')
    else:
        form = ChangePasswordForm(user=request.user)
    context = {
        'form': form,
    }
    return render(request, 'authenticate/change_password.html', context)

def register_user(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password1']
            email = form.cleaned_data['email']
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            new_user = keycloak_admin.create_user({"email": email,
                                       "username": username,
                                       "enabled": True,
                                       "firstName": first_name,
                                       "lastName": last_name,
                    "credentials": [{"value": password,"type": "password",}]})
            form.save()
            messages.success(request, 'You have been registered and logged in successfully with Keycloak')
            return redirect('login_keycloak')
        else:
            messages.warning(request, 'Registration failed. Please check the form.')
            return redirect('register')
    else:
        form = SignUpForm()
    context = {
        'form': form,
    }
    return render(request, 'authenticate/register.html', context)

    
def login_keycloak(request):
    redirect_uri = request.build_absolute_uri('/keycloak-callback/')
    login_url = keycloak_openid.auth_url(redirect_uri=redirect_uri, scope='openid')
    return redirect(login_url)

def keycloak_callback(request):
    code = request.GET.get('code')
    token_response = keycloak_openid.token(code=code, redirect_uri=request.build_absolute_uri('/keycloak-callback/'), grant_type='authorization_code')

    access_token = token_response['access_token']
    refresh_token = token_response['refresh_token']

    request.session['access_token'] = access_token
    request.session['refresh_token'] = refresh_token

    user_info = keycloak_openid.userinfo(token=access_token)
    
    keycloak_auth_backend = KeycloakAuthenticationBackend()
    user = keycloak_auth_backend.authenticate(request=request, keycloak_user_info=user_info)
    if user is not None:
        login(request, user)
        messages.success(request, 'Successfully logged in with Keycloak')
        return redirect('home')

    return redirect('home')

def home(request):
    if request.user.is_authenticated:
        token_info = keycloak_openid.introspect(request.session['access_token'])

        if not token_info['active']:
            refresh_token_response = keycloak_openid.refresh_token(request.session['refresh_token'])
            request.session['access_token'] = refresh_token_response['access_token']

        user_info = keycloak_openid.userinfo(token=request.session['access_token'])
        translated_user_info = {
            'name': _(user_info['name']),
            'preferred_username': _(user_info['preferred_username']),
            'email': _(user_info['email']),
    }
        return render(request, 'authenticate/home.html', {'user_info': translated_user_info})
    else:
        return render(request, 'authenticate/home.html')


class SignUp(generics.GenericAPIView):
    def get(self, request):
        form = SignUpForm()
        return render(request, 'authenticate/register.html', {'form': form})
    
    def post(self, request):
        form = SignUpForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password1']
            email = form.cleaned_data['email']
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            new_user = keycloak_admin.create_user({
                "email": email,
                "username": username,
                "enabled": True,
                "firstName": first_name,
                "lastName": last_name,
                "credentials": [{"value": password, "type": "password"}]
            })
            form.save()
            messages.success(request, _('You have been registered and logged in successfully with Keycloak'))
            return redirect('login_keycloak')
        else:
            messages.warning(request, _('Registration failed. Please check the form.'))
            return redirect('register')
        
class Signin(generics.GenericAPIView):
    def get(self, request):
        redirect_uri = request.build_absolute_uri('/keycloak-callback/')
        login_url = keycloak_openid.auth_url(redirect_uri=redirect_uri, scope='openid')
        return redirect(login_url)
    
class KeycloakCallback(generics.GenericAPIView):
    def get(self, request):
        code = request.GET.get('code')
        token_response = keycloak_openid.token(
            code=code,
            redirect_uri=request.build_absolute_uri('/keycloak-callback/'),
            grant_type='authorization_code'
        )
        access_token = token_response['access_token']
        refresh_token = token_response['refresh_token']

        request.session['access_token'] = access_token
        request.session['refresh_token'] = refresh_token
        user_info = keycloak_openid.userinfo(token=access_token)
        
        keycloak_auth_backend = KeycloakAuthenticationBackend()
        user = keycloak_auth_backend.authenticate(request=request, keycloak_user_info=user_info)
        if user is not None:
            login(request, user)
            messages.success(request, _('Successfully logged in with Keycloak'))
            return redirect('home')

        return redirect('home')

class HomePage(generics.GenericAPIView):
    def get(self, request):
        if request.user.is_authenticated:
            token_info = keycloak_openid.introspect(request.session['access_token'])

            if not token_info['active']:
                refresh_token_response = keycloak_openid.refresh_token(request.session['refresh_token'])
                request.session['access_token'] = refresh_token_response['access_token']
                
            user_info = keycloak_openid.userinfo(token=request.session['access_token'])
            return render(request, 'home.html', {'user_info': user_info})
        else:
            return render(request, 'home.html', {'user_info': {}})