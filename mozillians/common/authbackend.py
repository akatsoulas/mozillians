import base64
import hashlib
import re

from django.conf import settings
from django.contrib.auth.models import User
from django.contrib import messages

from mozilla_django_oidc.auth import OIDCAuthenticationBackend

from mozillians.users.models import IdpProfile
from mozillians.users.tasks import send_userprofile_to_cis


SSO_AAL_SCOPE = 'https://sso.mozilla.com/claim/AAI'


def calculate_username(email):
    """Calculate username from email address."""

    email = email.split('@')[0]
    username = re.sub(r'[^\w.@+-]', '-', email)
    username = username[:settings.USERNAME_MAX_LENGTH]
    suggested_username = username
    count = 0

    while User.objects.filter(username=suggested_username).exists():
        count += 1
        suggested_username = '%s%d' % (username, count)

        if len(suggested_username) > settings.USERNAME_MAX_LENGTH:
            # We failed to calculate a name for you, default to a
            # email digest.
            return base64.urlsafe_b64encode(hashlib.sha1(email).digest()).rstrip('=')

    return suggested_username


class MozilliansAuthBackend(OIDCAuthenticationBackend):
    """Override OIDCAuthenticationBackend to provide custom functionality."""

    def get_or_create_user(self, *args, **kwargs):
        return super(MozilliansAuthBackend, self).get_or_create_user(*args, **kwargs)

    def get_username(self, claims):
        """
        If we are creating a user and the Search Service already has a username,
        we will use that. Otherwise, we will get the username derived from username_algo.
        """
        return super(MozilliansAuthBackend, self).get_username(claims)

    def create_user(self, claims):
        user = super(MozilliansAuthBackend, self).create_user(claims)
        # Ensure compatibility with OIDC conformant mode
        auth0_user_id = claims.get('user_id') or claims.get('sub')

        IdpProfile.objects.create(
            profile=user.userprofile,
            auth0_user_id=auth0_user_id,
            email=claims.get('email'),
            primary=True
        )

        return user

    def filter_users_by_claims(self, claims):
        """Override default method to store claims."""
        self.claims = claims
        users = super(MozilliansAuthBackend, self).filter_users_by_claims(claims)

        # Checking the primary email returned 0 users,
        # before creating a new user we should check if the identity returned exists
        if not users:
            # Ensure compatibility with OIDC conformant mode
            auth0_user_id = claims.get('user_id') or claims.get('sub')
            idps = IdpProfile.objects.filter(auth0_user_id=auth0_user_id)
            user_ids = idps.values_list('profile__user__id', flat=True).distinct()
            return self.UserModel.objects.filter(id__in=user_ids)
        return users

    def check_authentication_method(self, user):
        """Check which Identity is used to login.

        This method, depending on the current status of the IdpProfile
        of a user, enforces MFA logins and creates the IdpProfiles.
        Returns the object (user) it was passed unchanged.
        """
        if not user:
            return None

        profile = user.userprofile
        # Ensure compatibility with OIDC conformant mode
        auth0_user_id = self.claims.get('user_id') or self.claims.get('sub')
        email = self.claims.get('email')
        aal_scope = self.claims.get(SSO_AAL_SCOPE)
        is_mfa = True
        if not aal_scope or aal_scope != ['2FA']:
            is_mfa = False

        # Grant an employee vouch if the user has the 'hris_is_staff' group
        groups = self.claims.get('https://sso.mozilla.com/claim/groups')
        if groups and 'hris_is_staff' in groups:
            profile.auto_vouch()

        # Get or create new `user_id`
        obj, _ = IdpProfile.objects.get_or_create(
            profile=profile,
            email=email,
            auth0_user_id=auth0_user_id)

        if profile.groups.filter(is_access_group=True).exists() and not is_mfa:
            msg = ('Members and Curators of Access Groups need to use a 2FA'
                   ' authentication method to login.')
            messages.error(self.request, msg)
            return None

        # With account deracheting we will always get the same Auth0 user id. Mark it as primary
        if not obj.primary:
            obj.primary = True
            IdpProfile.objects.filter(profile=profile).exclude(id=obj.id).update(primary=False)

        # Update/Save the Github username
        if 'github|' in auth0_user_id:
            obj.username = self.claims.get('nickname', '')
        # Save once
        obj.save()

        # Update CIS
        send_userprofile_to_cis.delay(profile.pk)
        return user

    def authenticate(self, **kwargs):
        """Override default method to add multiple Identity Profiles in an account."""
        user = super(MozilliansAuthBackend, self).authenticate(**kwargs)

        return self.check_authentication_method(user)
