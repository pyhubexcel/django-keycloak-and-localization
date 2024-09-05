# Design phases for kds-oidc-reference

## PHASE 1 - OIDC flow between Keycloak and Django - **COMPLETE**
 - Create a reference implementation of standard Keycloak providing OIDC Identity Provider to Django application.
 - All passwords should only be entered/known to Keycloak
 - Initial public landing page in Django that provides a link to 'Login'
 - Login flow should follow the OIDC Authorization Code flow
   - Login dialog is from Keycloak server itself
   - Redirect URL should send user back to Django after successful login
 - Private landing page only for logged in users that displays username and details to prove login was successful.

## PHASE 2 - Code base setup - **COMPLETE**

 - Clone https://dev.azure.com/openskygroup/SoftwareServices/_git/kds-oidc-reference 
   - /keycloak-23.0.6      - directory of keycloak
       - /data/import      - generated from `bin/kc.bat export --dir ./data/import`. May not be needed if h2 database persists
                             
   - /django               - vscode project for django app
       - requirements.txt  - generated from pip freeze > requirements.txt

 - views.py
   - def home
     - Unathenticated, a message "Please log in" and a button taking them to keycloak login
     - Authenticated, rendering authenticated/home.html

 - view/util/keycloak.py
   - callback_url
   - register_user
   - valid_session(request) ? true|false
   - (anything else to centralize keycloak generic functions)

## PHASE 3 - kds-oidc-reference identity broker to validate Azure - **COMPLETE**

 - https://www.keycloak.org/docs/latest/server_admin/#_identity_broker 
   - Microsoft (Azure Entra)
     - Following this reference we have the following OIDC app registered:
       https://www.hcl-software.com/blog/versionvault/how-to-configure-microsoft-azure-active-directory-as-keycloak-identity-provider-to-enable-single-sign-on-for-hcl-compass
     - ClientID: `0f8e37bb-c871-41fe-8287-3856f2b3f139`
     - ClientSecret: `PLd8Q~GQmjTIT62sHCCkaD3zMxivTosb4dqEadxr`
     - ClientSecretID: `79e9fb18-24a1-4746-843d-d72b386c217d`
       - Don't think this should be needed, but including for completeness
     - DirectoryID: `566b5956-d590-485c-9daf-f83e66eaaadb`
 - views.py
   - def home
     - Unathenticated, a message "Please log in" and a button taking them to keycloak login, where they can optionally select **Azure** login
     - Authenticated, rendering authenticated/home.html that is able to display basic details about azure user, specifically the email address, user name, scopes?

## PHASE 4 - Advanced refresh and token sharing methods
 - We need to document and understand where to configure the access_token lifespan
   - Validated Keycloak login by setting token lifetime to 5 minutes.
   - Does that configuration work also for Azure login, or other configuration needed.
   - Scenario 1 - Verify that refresh tokens are working as expected:
     - After logging in, if a user sits idle past the 5m mark, and then refreshes the authenticated page, confirm they are still logged in.
   - Scenario 2a - (ALREAD VALIDATED) If a user logs in, closes the browser, and reopens the browser to the authenticated page, they should stay logged in.
   - Scenario 2b - If a user logs in, closes the browser, sits idle past the 5m mark, then reopens the browser to the authenticated page, they should stay logged in.
 - To authenticate against the below APIs you may need to enable Resource Flow in Keycloak
   - https://auth0.com/docs/get-started/authentication-and-authorization-flow/resource-owner-password-flow
   - Endpoint in keycloak to request tokens
     - Need to pass their username+password into the API call
     - Get an access_token and refresh_token in the results
     - Use the 'Bearer access_token' directly int the below calls to Django
   - Notes:
     - Username and password are only ever sent to a Keycloak API
     - Username and password are never setn to a Django or Flask API
     - Access token is only sent to Django or Flask APIs
 - Add to the Django project two JSON REST APIs
   - **NOTE** - make sure @csrf_exempt restrictions are not in place for api/v1/**
   - Django library: https://www.django-rest-framework.org/
   - api/v1/unauthenticated
     - Allowed for any Postman/REST call and returns any JSON value to prove anonymous query.
   - api/vi/authenticated
     - Ensure user has a valid token and in JSOM format return similar details as the athenticated view in Django.
     - The goal is to have one login via Django and also be able to access these APIs with same token
 - Add to the code repository a default basic Flask folder with a Python flask project that contains two JSON REST APIs
   - Current OAuth library used: https://pypi.org/project/Flask-of-Oil/
   - api/v1/unauthenticated
     - Allowed for any Postman/REST call and returns any JSON value to prove anonymous query.
   - api/vi/authenticated
     - Ensure user has a valid token and in JSOM format return similar details as the athenticated view in Django.
     - The goal is to have one login via Django and also be able to access Flask APIs with same token

## PHASE 5 - Expanding authentication methods
 - Currently everything has been accessed through a variation of the Authorzation Code Flow https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow
 - Additionally support automated systems through the Client Credentials Flow https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-credentials-flow
   - This is not expected to require Azure auth
   - Validated by a simple python script which logs in as an API (Keycloak) user and uses tokens to query authenticated APIs in Django and Flask 
 - Finally for CLI type access from a user, support the Device Code Flow https://auth0.com/docs/get-started/authentication-and-authorization-flow/device-authorization-flow
   - So this is an interactive login, so it is expected to also work with Azure user.
   - Validated by python script which logs in as an Azure user via cli and uses tokens to query authenticated APIs in Django and Flask
   - Do not need to cache logins like `az login` does, even though it is the same type of flow.

## PHASE 6 - Advanced permission configurations

 - Keycloak assigned permission groups
   - GOAL: We want to avoid requiring user to login in once, before we can assign permissions.
   - Can we assign specific permission GROUP level names or scopes to users in Keycloak
   - On the authenticated page view where we show user name, user ID and user email - additionally show assigned scopes

 - User management
   - GOAL: We want to be able to give selective control to end-user admins to reduce admin load on OSG
   - Will need to review how to create the following user profiles:
     - Keycloak admin - (already done, likely the same Keycloak account that can create new realms)
     - Realm admin - User than can only modify the currently assigned realm, but not create/view/edit any other realms
     - User admin - User that can only create/add new user accounts to their assigned realm, but no other realm edits
     - User - User that can only see their own Keycloak account, perform change password, but no other action

 - User group management (unlikely to be Keycloak supported, may need Django view)
   - GOAL: 3PL customers often have sub-vendors per warehouse that may need per-warehouse admins
   - Instead of a realm wide "user admin" as above, can we create a group/scope with a local user admin that can assign users within that scope/group
     - SCOPE: arcadia_hzl01  (this would match a permission group in ECB with same name)
       - User admin: hzl01_admin@arcadiacold.com
         - Scopes: arcadia_hzl01, arcadia_hzl01_user_admin
         - They can create additional users that are limited to arcadia_hzl01 scope/grouping
         - They can't create additional users with different scopes than their own.
       - Regular users: user1@arcadiacold.com
         - Scopes: arcadia_hzl01
       - Regular users: user2@arcadiacold.com
         - Scopes: arcadia_hzl01
       - EXAMPLE RESTRICTED: user3@arcadiacold.com
         - Scopes: arcadia_atl01
         - Based on scopes hzl01_admin@arcadiacold.com should not be able to create this user
     - SCOPE: arcadia_atl01  (this would match a permission group in ECB with same name)
       - User admin: atl01_admin@arcadiacold.com
         - Scopes: arcadia_atl01, arcadia_atl01_user_admin
         - They can create additional users that are limited to arcadia_hzl01 scope/grouping
         - They can't create additional users with different scopes than their own.
       - Regular users: user4@arcadiacold.com
         - Scopes: arcadia_atl01
     - Functional approach:
       - If these types of group permissions are available directly in Keycloak - PREFERRED
         - Potentially a opensource plugin required/possible pay - SECOND PREFERRED
         - If easiest to create a Keycloak plugin for this - THIRD PREFERRED
       - FOURTH PREFERRED - Django UI view for user/group management
         - Django logic will ensure users can only create similarly scoped regular users
         - Will need to use Keycloak APIs to define additional users within the specified groups
         - Will need to ensure this can be done securly to avoid "workarounds"


yes reshma on friday we had a call with jonathan regarding the query related to tasks and i had asked some questions on phase 4. so he had updated the phase 4 and added some point like To authenticate against the APIs and may need to enable the Resource Flow in Keycloak and Endpoint in keycloak to request the tokens so i'm working on that. that's all from my side.

yes reshma today i will be working on the same like yesterday and yeah actually i have created the functions for the api and now need to create a class method instead of the functions using generic views and @csrf_exempt decorator so yeah today i'll be working on that.