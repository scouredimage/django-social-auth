"""Views"""
from django.conf import settings
from django.http import HttpResponseRedirect, HttpResponse, \
                        HttpResponseServerError
from django.core.urlresolvers import reverse
from django.db import transaction
from django.contrib.auth import login, REDIRECT_FIELD_NAME
from django.contrib.auth.decorators import login_required

from social_auth.backends import get_backend
from social_auth.utils import sanitize_redirect

from urlparse import parse_qsl
from urllib import urlencode


DEFAULT_REDIRECT = getattr(settings, 'SOCIAL_AUTH_LOGIN_REDIRECT_URL', '') or \
                   getattr(settings, 'LOGIN_REDIRECT_URL', '')
NEW_USER_REDIRECT = getattr(settings, 'SOCIAL_AUTH_NEW_USER_REDIRECT_URL', '')
SOCIAL_AUTH_LAST_LOGIN = getattr(settings, 'SOCIAL_AUTH_LAST_LOGIN',
                                 'social_auth_last_login_backend')
REDIRECT_QUERY_STRING = 'social_auth_login_query_string'


def auth(request, backend):
    """Start authentication process"""
    complete_url = getattr(settings, 'SOCIAL_AUTH_COMPLETE_URL_NAME',
                           'complete')
    return auth_process(request, backend, complete_url)


@transaction.commit_on_success
def complete(request, backend):
    """Authentication complete view, override this view if transaction
    management doesn't suit your needs."""
    return complete_process(request, backend)


def complete_process(request, backend):
    """Authentication complete process"""
    backend = get_backend(backend, request, request.path)
    if not backend:
        return HttpResponseServerError('Incorrect authentication service')

    try:
        user = backend.auth_complete()
    except ValueError, e:  # some Authentication error ocurred
        user = None
        error_key = getattr(settings, 'SOCIAL_AUTH_ERROR_KEY', None)
        if error_key:  # store error in session
            request.session[error_key] = str(e)

    if user and getattr(user, 'is_active', True):
        # Store query parameters passed in to login url (if any).
        # This gets lost during auth login processing!
        query_string = request.session.pop(REDIRECT_QUERY_STRING, '')

        login(request, user)
        if getattr(settings, 'SOCIAL_AUTH_SESSION_EXPIRATION', True):
            # Set session expiration date if present and not disabled by
            # setting. Use last social-auth instance for current provider,
            # users can associate several accounts with a same provider.
            #
            # user.social_user is the used UserSocialAuth instance defined
            # in authenticate process
            social_user = user.social_user
            if social_user.expiration_delta():
                request.session.set_expiry(social_user.expiration_delta())

        if NEW_USER_REDIRECT and getattr(user, 'is_new', False):
            url = request.session.pop(REDIRECT_FIELD_NAME, '')
            if not url:
                url = NEW_USER_REDIRECT
            else:
                sep = '?' if NEW_USER_REDIRECT.find('?') == -1 else '&'
                url = '%s%c%s=%s' % (NEW_USER_REDIRECT, sep, REDIRECT_FIELD_NAME, url)
        else:
            url = request.session.pop(REDIRECT_FIELD_NAME, '') or DEFAULT_REDIRECT

        # store last login backend name in session
        request.session[SOCIAL_AUTH_LAST_LOGIN] = social_user.provider

        # tack on login url query parameters
        if query_string:
            separator = '?' if url.find('?') == -1 else '&'
            url += '%c%s' % (separator, query_string)

    else:
        url = getattr(settings, 'LOGIN_ERROR_URL', settings.LOGIN_URL)

    return HttpResponseRedirect(url)


@login_required
def associate(request, backend):
    """Authentication starting process"""
    complete_url = getattr(settings, 'SOCIAL_AUTH_ASSOCIATE_URL_NAME',
                           'associate_complete')
    return auth_process(request, backend, complete_url)


@login_required
def associate_complete(request, backend):
    """Authentication complete process"""
    backend = get_backend(backend, request, request.path)
    if not backend:
        return HttpResponseServerError('Incorrect authentication service')
    backend.auth_complete(user=request.user)
    url = request.session.pop(REDIRECT_FIELD_NAME, '') or DEFAULT_REDIRECT
    return HttpResponseRedirect(url)


@login_required
def disconnect(request, backend):
    """Disconnects given backend from current logged in user."""
    backend = get_backend(backend, request, request.path)
    if not backend:
        return HttpResponseServerError('Incorrect authentication service')
    backend.disconnect(request.user)
    url = request.REQUEST.get(REDIRECT_FIELD_NAME, '') or DEFAULT_REDIRECT
    return HttpResponseRedirect(url)


def auth_process(request, backend, complete_url_name):
    """Authenticate using social backend"""
    redirect = reverse(complete_url_name, args=(backend,))
    backend = get_backend(backend, request, redirect)
    if not backend:
        return HttpResponseServerError('Incorrect authentication service')

    # Check and sanitize a user-defined GET/POST redirect_to field value.
    redirect = sanitize_redirect(request.get_host(),
                                 request.REQUEST.get(REDIRECT_FIELD_NAME))

    request.session[REDIRECT_FIELD_NAME] = redirect

    # Store query parameters (if any). These will be tacked on to the end of
    # the login redirect url in complete_process().
    all_params = dict(parse_qsl(request.META['QUERY_STRING']))
    params = [(k, v) for k, v in all_params.items() if not k == REDIRECT_FIELD_NAME]
    request.session[REDIRECT_QUERY_STRING] = urlencode(params)

    if backend.uses_redirect:
        return HttpResponseRedirect(backend.auth_url())
    else:
        return HttpResponse(backend.auth_html(),
                            content_type='text/html;charset=UTF-8')
