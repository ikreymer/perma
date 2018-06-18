import Cookie
#import StringIO
from collections import defaultdict
from io import BytesIO
import os
import random
#import threading
import re
from urlparse import urljoin
import requests
import string
import sys
from datetime import datetime

from django.db import close_old_connections
from django.template import loader
from django.test import RequestFactory

# configure Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "perma.settings")
import django
django.setup()

from django.conf import settings
from django.core.handlers.wsgi import WSGIRequest
from django.core.files.storage import default_storage
from django.core.exceptions import DisallowedHost
from django.core.cache import cache as django_cache
from django.apps import apps

CDXLine = apps.get_model('perma', 'CDXLine')
Link = apps.get_model('perma', 'Link')
Mirror = apps.get_model('lockss', 'Mirror')

import logging
logger = logging.getLogger(__name__)


newstyle_guid_regex = r'[A-Z0-9]{1,4}(-[A-Z0-9]{4})+'  # post Nov. 2013
oldstyle_guid_regex = r'0[a-zA-Z0-9]{9,10}'  # pre Nov. 2013
GUID_REGEX = r'(%s|%s)' % (oldstyle_guid_regex, newstyle_guid_regex)
WARC_STORAGE_PATH = os.path.join(settings.MEDIA_ROOT, settings.WARC_STORAGE_DIR)
#thread_local_data = threading.local()


from warcio.limitreader import LimitReader
from pywb.warcserver.basewarcserver import BaseWarcServer
from pywb.warcserver.index.cdxobject import CDXObject
from pywb.utils.wbexception import NotFoundException
from pywb.utils.canonicalize import canonicalize
from pywb.utils.loaders import BlockLoader, LocalFileLoader
from pywb.warcserver.handlers import DefaultResourceHandler, HandlerSeq, ResourceHandler
from pywb.warcserver.index.aggregator import SimpleAggregator, GeventTimeoutAggregator
from pywb.warcserver.index.indexsource import BaseIndexSource


# ============================================================================
class PermaWarcServer(BaseWarcServer):
    pass


# ============================================================================
def app():
    BlockLoader.loaders['file'] = CachedFileLoader

    server = PermaWarcServer(debug=True)

    handler = DefaultResourceHandler(SimpleAggregator({'perma': PermaIndexSource()}),
                                     warc_paths=get_archive_path())

    server.add_route('/perma', handler)

    return server


# ============================================================================
def get_archive_path():
    # Get root storage location for warcs, based on default_storage.
    # archive_path should be the location pywb can find warcs, like 'file://generated/' or 'http://perma.s3.amazonaws.com/generated/'
    # We can get it by requesting the location of a blank file from default_storage.
    # default_storage may use disk or network storage depending on config, so we look for either a path() or url()
    try:
        archive_path = 'file://' + default_storage.path('') + '/'
        print(archive_path)

    except NotImplementedError:
        archive_path = default_storage.url('')
        archive_path = archive_path.split('?', 1)[0]  # remove query params

    # must be ascii, for some reason, else you'll get
    # 'unicode' object has no attribute 'get'
    return archive_path.encode('ascii', 'ignore')


# ============================================================================
class PermaIndexSource(BaseIndexSource):
    def load_index(self, params):
        """Parse the GUID and find the CDXLine in the DB"""
        guid = params.get('guid', '')
        url = params['url']

        cache_key = Link.get_cdx_cache_key(guid)
        cached_cdx = django_cache.get(cache_key)
        #redirect_matcher = re.compile(r' 30[1-7] ')
        if cached_cdx is None or url == 'auto':
            try:
                # This will filter out links that have user_deleted=True
                link = Link.objects.get(guid=guid)
            except Link.DoesNotExist:
                raise NotFoundException(guid)

            if url == 'auto':
                url = link.ascii_safe_url
                params['url'] = url
                params['key'] = canonicalize(url)

                # This is a bare request to /warc/1234-5678/ -- return so we can send a forward to submitted_url in PermaGUIDHandler.
            #    wbrequest.custom_params['guid'] = guid
            #    wbrequest.custom_params['url'] = link.ascii_safe_url
            #    return

            # Legacy archives didn't generate CDXLines during
            # capture so generate them on demand if not found, unless
            # A: the warc capture hasn't been generated OR
            # B: we know other cdx lines have already been generated
            #    and the requested line is simply missing
            lines = CDXLine.objects.filter(link_id=link.guid)

            if not lines:
                lines = CDXLine.objects.create_all_from_link(link)

            # build a lookup of all cdx lines for this link indexed by urlkey, like:
            # cached_cdx = {'urlkey1':['raw1','raw2'], 'urlkey2':['raw3','raw4']}
            cached_cdx = defaultdict(list)
            for line in lines:
                cached_cdx[line.urlkey].append(str(line.raw))

            # remove any redirects if we also have a non-redirect capture for the same URL, to prevent redirect loops
            #for urlkey, lines in cached_cdx.iteritems():
            #    if len(lines) > 1:
            #        lines_without_redirects = [line for line in lines if not redirect_matcher.search(line)]
            #        if lines_without_redirects:
            #            cached_cdx[urlkey] = lines_without_redirects

            # record whether link is private so we can enforce permissions
            cached_cdx['is_private'] = link.is_private

            django_cache.set(cache_key, cached_cdx)

        # enforce permissions
        #if cached_cdx.get('is_private'):
            # if user is allowed to access this private link, they will have a cookie like GUID=<token>,
            # which can be validated with link.validate_access_token()
        #    cookie = Cookie.SimpleCookie(wbrequest.env.get('HTTP_COOKIE')).get(guid)
        #    if not cookie:
        #        raise CustomTemplateException(status='400 Bad Request',
        #                                      template_path='archive/missing-cookie.html',
        #                                      template_kwargs={
        #                                          'content_host': settings.WARC_HOST,
        #                                      })
        #    if not Link(pk=guid).validate_access_token(cookie.value, 3600):
        #        raise_not_found(wbrequest.wb_url, timestamp=wbrequest.wb_url.timestamp)

        # check whether archive contains the requested URL
        try:
            #urlkey = surt(wbrequest.wb_url.url)
            urlkey = params['key']
            cdx_lines = cached_cdx.get(urlkey)
        except ValueError:
            # calling surt on malformed urls (e.g. typos in protocol, whitespace)
            # throws a value error; let's handle like a normal 404
            cdx_lines = None

        if not cdx_lines:
            #raise_not_found(wbrequest.wb_url, timestamp=wbrequest.wb_url.timestamp)
            raise NotFoundException(url)

        def do_load(cdx_lines):
            for cdx in cdx_lines:
                cdx = CDXObject(cdx)
                cdx['source'] = guid
                yield cdx

        return do_load(cdx_lines)

        # Store the line for use in PermaCDXSource
        # so we don't need to hit the DB again
        #wbrequest.custom_params['lines'] = cdx_lines
        #wbrequest.custom_params['guid'] = guid

        # Adds the Memento-Datetime header
        # Normally this is done in MementoReqMixin#_parse_extra
        # but we need the GUID to make the DB query and that
        # isn't parsed from the url until this point
        #wbrequest.wb_url.set_replay_timestamp(CDXLine(raw=cdx_lines[0]).timestamp)



# ============================================================================
class CachedFileLoader(LocalFileLoader):
    """
        File loader that stores requested file in key-value cache for quick retrieval.
    """
    def load(self, url, offset=0, length=-1):

        # first try to fetch url contents from cache
        cache_key = Link.get_warc_cache_key(url.split(settings.MEDIA_ROOT, 1)[-1])

        mirror_name_cache_key = cache_key + '-mirror-name'
        mirror_name = ''

        file_contents = django_cache.get(cache_key)

        if file_contents is None:
            # url wasn't in cache -- load contents

            # try fetching from each mirror in the LOCKSS network, in random order
            if settings.USE_LOCKSS_REPLAY:
                file_contents, mirror_name = self.load_lockss(url)

            # If url wasn't in LOCKSS yet or LOCKSS is disabled, fetch from local storage using super()
            if file_contents is None:
                file_contents = super(CachedFileLoader, self).load(url).read()
                logging.debug("Got content from local disk")

            # cache file contents
            # use a short timeout so large warcs don't evict everything else in the cache
            django_cache.set(cache_key, file_contents, timeout=60)
            django_cache.set(mirror_name_cache_key, mirror_name, timeout=60)

        else:
            mirror_name = django_cache.get(mirror_name_cache_key)

        # set wbrequest.mirror_name so it can be displayed in template later
        #thread_local_data.wbrequest.mirror_name = mirror_name

        # turn string contents of url into file-like object
        #afile = StringIO.StringIO(file_contents)
        afile = BytesIO(file_contents)

        # --- from here down is taken from super() ---
        if offset > 0:
            afile.seek(offset)

        if length >= 0:
            return LimitReader(afile, length)
        else:
            return afile

    def load_lockss(self, url):
        mirrors = Mirror.get_cached_mirrors()
        random.shuffle(mirrors)

        file_contents = None
        mirror_name = ''

        for mirror in mirrors:
            lockss_key = url.replace('file://', '').replace(WARC_STORAGE_PATH, 'https://' + settings.HOST + '/lockss/fetch')
            lockss_url = urljoin(mirror['content_url'], 'ServeContent')
            try:
                logging.info("Fetching from %s?url=%s" % (lockss_url, lockss_key))
                response = requests.get(lockss_url, params={'url': lockss_key})
                assert response.ok
                file_contents = response.content
                mirror_name = mirror['name']
                logging.info("Got content from lockss")
            except (requests.ConnectionError, requests.Timeout, AssertionError) as e:
                logging.info("Couldn't get from lockss: %s" % e)

        return file_contents, mirror_name



