from tastypie.validation import Validation
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
from netaddr import IPAddress, IPNetwork
from mimetypes import MimeTypes
import imghdr

from django.conf import settings

class LinkValidation(Validation):
    def is_valid_ip(self, ip):
        for banned_ip_range in settings.BANNED_IP_RANGES:
            if IPAddress(ip) in IPNetwork(banned_ip_range):
                return False
        return True

    def is_valid_size(self, headers):
        try:
            if int(headers.get('content-length', 0)) > 1024 * 1024 * 100:
                return False
        except ValueError:
            # Weird -- content-length header wasn't an integer. Carry on.
            pass
        return True

    def is_valid_file(self, upload, mime_type):
        # Make sure files are not corrupted.
        if mime_type == 'image/jpeg':
            return imghdr.what(upload) == 'jpeg'
        elif mime_type == 'image/png':
            return imghdr.what(upload) == 'png'
        elif mime_type == 'image/gif':
            return imghdr.what(upload) == 'gif'
        elif mime_type == 'application/pdf':
            doc = PdfFileReader(upload)
            if doc.numPages >= 0:
                return True
        return False

    def is_valid(self, bundle, request=None):
        # We've received a request to archive a URL. That process is managed here.
        # We create a new entry in our datastore and pass the work off to our indexing
        # workers. They do their thing, updating the model as they go. When we get some minimum
        # set of results we can present the user (a guid for the link), we respond back.

        if not bundle.data:
            return {'__all__': 'No data provided.'}
        errors = {}

        if bundle.data.get('url', '') == '':
            errors['url'] = "URL cannot be empty."
        else:
            try:
                validate = URLValidator()
                validate(bundle.obj.submitted_url)

                # Don't force URL resolution validation if a file is provided
                if not bundle.data.get('file'):
                    if not bundle.obj.ip:
                        errors['url'] = "Couldn't resolve domain."
                    elif not self.is_valid_ip(bundle.obj.ip):
                        errors['url'] = "Not a valid IP."
                    elif not bundle.obj.headers:
                        errors['url'] = "Couldn't load URL."
                    elif not self.is_valid_size(bundle.obj.headers):
                        errors['url'] = "Target page is too large (max size 1MB)."
            except ValidationError:
                errors['url'] = "Not a valid URL."

        if bundle.data.get('file'):
            mime = MimeTypes()
            mime_type = mime.guess_type(bundle.data.get('file').name)[0]

            # Get mime type string from tuple
            if not mime_type or not self.is_valid_file(bundle.data.get('file'), mime_type):
                errors['file'] = "Invalid file."
            elif bundle.data.get('file').size > settings.MAX_ARCHIVE_FILE_SIZE:
                errors['file'] = "File is too large."

        return errors
