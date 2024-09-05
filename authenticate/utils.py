from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from django.conf import settings

from keycloak import KeycloakAdmin, KeycloakOpenIDConnection, KeycloakOpenID


keycloak_openid = KeycloakOpenID(server_url=settings.KEYCLOAK['KEYCLOAK_SERVER_URL'],
                                realm_name=settings.KEYCLOAK['KEYCLOAK_REALM'],
                                client_id=settings.KEYCLOAK['KEYCLOAK_CLIENT_ID'],
                                client_secret_key=settings.KEYCLOAK['KEYCLOAK_CLIENT_SECRET']
                                )

config_well_known = keycloak_openid.well_known()

keycloak_connection = KeycloakOpenIDConnection(
                        server_url=settings.KEYCLOAK['KEYCLOAK_SERVER_URL'],
                        username=settings.USERNAME,
                        password=settings.PASSWORD,
                        realm_name=settings.KEYCLOAK['KEYCLOAK_REALM'],
                        # user_realm_name=settings.KEYCLOAK['KEYCLOAK_USER_REALM'],
                        client_id=settings.KEYCLOAK['KEYCLOAK_CLIENT_ID'],
                        client_secret_key=settings.KEYCLOAK['KEYCLOAK_CLIENT_SECRET'],
                        verify=True)
keycloak_admin = KeycloakAdmin(connection=keycloak_connection)

class KeycloakAuthenticationBackend(ModelBackend):
    def authenticate(self, request, keycloak_user_info=None, **kwargs):
        User = get_user_model()
        if keycloak_user_info is None:
            return None

        username = keycloak_user_info.get('preferred_username') or keycloak_user_info.get('sub')
        email = keycloak_user_info.get('email', '')

        user, created = User.objects.get_or_create(username=username, defaults={'email': email})
        if created:
            user.first_name = keycloak_user_info.get('given_name', '')
            user.last_name = keycloak_user_info.get('family_name', '')
            user.save()

        return user