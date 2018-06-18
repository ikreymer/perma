from io import BytesIO
import os
import sys

import logging
logger = logging.getLogger(__name__)

# pywb
from pywb.warcserver.basewarcserver import BaseWarcServer
from pywb.warcserver.index.cdxobject import CDXObject
from pywb.utils.wbexception import NotFoundException
from pywb.warcserver.handlers import DefaultResourceHandler
from pywb.warcserver.index.aggregator import SimpleAggregator
from pywb.warcserver.index.indexsource import BaseIndexSource

# django
from django.core.files.storage import default_storage
from django.apps import apps

CDXLine = apps.get_model('perma', 'CDXLine')
Link = apps.get_model('perma', 'Link')


# ============================================================================
def app():
    server = BaseWarcServer(debug=True)

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

        try:
            # This will filter out links that have user_deleted=True
            link = Link.objects.get(guid=guid)
        except Link.DoesNotExist:
            raise NotFoundException(guid)

        # query mysql for matching cdx lines
        lines = CDXLine.objects.filter(link_id=link.guid,
                                       raw__gte=params['key'],
                                       raw__lt=params['end_key']).order_by('raw')

        # enforce permissions
        if link.is_private:
            # TODO: readd cookie check?
            logging.debug('is private')

        def do_load(lines):
            for line in lines:
                cdx = CDXObject(str(line.raw))
                cdx['source'] = guid
                yield cdx

        return do_load(lines)
