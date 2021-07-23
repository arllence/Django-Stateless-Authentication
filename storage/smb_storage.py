from main.settings.file_test import store_file
from django.core.files.storage import Storage
from django.conf import settings
from django.utils.deconstruct import deconstructible
from django.core.files.base import File
from .smb_class import SMBSTORAGEUTILITY
storage_utility = SMBSTORAGEUTILITY()
try:
    from django.utils.six.moves.urllib import parse as urlparse
except ImportError:
    from urllib import parse as urlparse


@deconstructible
class SMBStorage(Storage):
    def __init__(self, option=None):
        if not option:
            option = settings.SMB_STORAGE_OPTIONS

    def exists(self, name):
        print("name")

    def _save(self, name, content):
        x = name.split("/")
        document_name = x[1]
        upload_content = store_file(content, document_name)
        return name

    def url(self, name):
        x = name.split("/")
        document_name = x[1]
        # read_file  = retrieve_file(document_name)
        # return name
        full_url = settings.DOCUMENT_URL + document_name
        return full_url
        # if self._base_url is None:
        #     raise ValueError("This file is not accessible via a URL.")
        # return urlparse.urljoin(self._base_url, name).replace('\\', '/')


@deconstructible
class SMBStorageFile(File):
    def __init__(self, name, storage, mode):
        self.name = name
        self._storage = storage
        self._mode = mode
        self._is_dirty = False
        self.file = io.BytesIO()
        self._is_read = False

    @property
    def size(self):
        if not hasattr(self, '_size'):
            self._size = self._storage.size(self.name)
        return self._size

    def readlines(self):
        if not self._is_read:
            self._storage._start_connection()
            self.file = self._storage._read(self.name)
            self._is_read = True
        return self.file.readlines()

    def read(self, num_bytes=None):
        if not self._is_read:
            self._storage._start_connection()
            self.file = self._storage._read(self.name)
            self._is_read = True
        return self.file.read(num_bytes)

    def write(self, content):
        if 'w' not in self._mode:
            raise AttributeError("File was opened for read-only access.")
        self.file = io.BytesIO(content)
        self._is_dirty = True
        self._is_read = True

    def close(self):
        if self._is_dirty:
            self._storage._start_connection()
            self._storage._put_file(self.name, self)
            self._storage.disconnect()
        self.file.close()
