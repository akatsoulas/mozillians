import requests
import urlparse

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.cache import never_cache

from mozillians.common.decorators import allow_public
from mozillians.dino_park.utils import UserAccessLevel, DinoErrorResponse


@never_cache
@login_required
def main(request):
    return render(request, 'dino_park/index.html', {})


@never_cache
def orgchart(request):
    """Internal routing to expose orgchart service."""
    scope = UserAccessLevel.get_privacy(request)
    if scope not in [UserAccessLevel.STAFF, UserAccessLevel.PRIVATE]:
        return DinoErrorResponse.get_error(DinoErrorResponse.PERMISSION_ERROR)

    url_parts = urlparse.ParseResult(
        scheme='http',
        netloc=settings.DINO_PARK_ORGCHART_SVC,
        path='/orgchart',
        params='',
        query='',
        fragment=''
    )
    url = urlparse.urlunparse(url_parts)
    resp = requests.get(url)
    resp.raise_for_status()
    return JsonResponse(resp.json(), safe=False)


@never_cache
def orgchart_get_by_username(request, path, username):
    """Internal routing to expose orgchart service by user_id."""
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        user = None
    scope = UserAccessLevel.get_privacy(request, user)
    if scope not in [UserAccessLevel.STAFF, UserAccessLevel.PRIVATE]:
        return DinoErrorResponse.get_error(DinoErrorResponse.PERMISSION_ERROR)

    url_parts = urlparse.ParseResult(
        scheme='http',
        netloc=settings.DINO_PARK_ORGCHART_SVC,
        path='/orgchart/{0}/{1}'.format(path, username),
        params='',
        query='',
        fragment=''
    )
    url = urlparse.urlunparse(url_parts)
    resp = requests.get(url)
    resp.raise_for_status()
    return JsonResponse(resp.json(), safe=False)


@never_cache
@allow_public
def search_simple(request, query):
    """Internal routing to expose simple search."""
    scope = UserAccessLevel.get_privacy(request)
    url_parts = urlparse.ParseResult(
        scheme='http',
        netloc=settings.DINO_PARK_SEARCH_SVC,
        path='/search/simple/{}/{}'.format(scope, query),
        params='',
        query=request.GET.urlencode(),
        fragment=''
    )
    url = urlparse.urlunparse(url_parts)
    resp = requests.get(url)
    resp.raise_for_status()
    return JsonResponse(resp.json(), safe=False)


@never_cache
@allow_public
def search_get_profile(request, username, scope=None):
    """Internal routing to expose search by user ID."""
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        user = None

    # If the user is authenticated and we don't have a match
    # in the db, probably the supplied value is not a username
    if not user and request.user.is_authenticated():
        return DinoErrorResponse.get_error(
            DinoErrorResponse.ATTRIBUTE_ERROR,
            status_code=503,
            attribute='Attribute username, value {}'.format(username)
        )

    # If there is not a supplied scope, let's get one
    if not scope:
        scope = UserAccessLevel.get_privacy(request, user)
    url_parts = urlparse.ParseResult(
        scheme='http',
        netloc=settings.DINO_PARK_SEARCH_SVC,
        path='/search/get/{}/{}'.format(scope, username),
        params='',
        query='',
        fragment=''
    )
    url = urlparse.urlunparse(url_parts)
    resp = requests.get(url)
    resp.raise_for_status()
    return JsonResponse(resp.json(), safe=False)
