from __future__ import with_statement
from urlparse import urlparse
import os.path


def sanitize_redirect(host, redirect_to):
    """
    Given the hostname and an untrusted URL to redirect to,
    this method tests it to make sure it isn't garbage/harmful
    and returns it, else returns None.

    See http://code.djangoproject.com/browser/django/trunk/django/contrib/auth/views.py#L36

    >>> print sanitize_redirect('myapp.com', None)
    None
    >>> print sanitize_redirect('myapp.com', '')
    None
    >>> print sanitize_redirect('myapp.com', {})
    None
    >>> print sanitize_redirect('myapp.com', 'http://notmyapp.com/path/')
    None
    >>> print sanitize_redirect('myapp.com', 'http://myapp.com/path/')
    http://myapp.com/path/
    >>> print sanitize_redirect('myapp.com', '/path/')
    /path/
    >>> print sanitize_redirect('myapp.com', 'http://test.myapp.com/path/')
    http://test.myapp.com/path/
    """
    # Quick sanity check.
    if not redirect_to:
        return None

    # Heavier security check, don't allow redirection to a different host.
    try:
        netloc = urlparse(redirect_to)[1]
    except TypeError:  # not valid redirect_to value
        return None

    if netloc and not getDomain(host) == getDomain(netloc):
        return None

    return redirect_to

# load tlds, ignore comments and empty lines
with open(os.path.dirname(__file__) + "/data/effective_tld_names.dat") as tldFile:
    TLDS = [line.strip() for line in tldFile if line[0] not in "/\n"]

def getDomain(netloc):
    try:
      netloc = netloc[0:netloc.index(':')]
    except ValueError:
      pass

    urlElements = netloc.split('.')
    # urlElements = ["abcde","co","uk"]

    for i in range(-len(urlElements),0):
        lastIElements = urlElements[i:]
        #    i=-3: ["abcde","co","uk"]
        #    i=-2: ["co","uk"]
        #    i=-1: ["uk"] etc

        candidate = ".".join(lastIElements) # abcde.co.uk, co.uk, uk
        wildcardCandidate = ".".join(["*"]+lastIElements[1:]) # *.co.uk, *.uk, *
        exceptionCandidate = "!"+candidate

        # match tlds:
        if (exceptionCandidate in TLDS):
            return ".".join(urlElements[i:]) 
        if (candidate in TLDS or wildcardCandidate in TLDS):
            return ".".join(urlElements[i-1:])
            # returns "abcde.co.uk"

    raise ValueError("Domain not in global list of TLDs")

if __name__ == '__main__':
    import doctest
    doctest.testmod()
