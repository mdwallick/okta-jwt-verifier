import json
import os
import time
import traceback

from pymemcache.client.base import Client
from oktajwt.cache_plugin import CachePlugin
from oktajwt.exceptions import CacheObjectNotFoundError

class MemCachedPlugin(CachePlugin):

    MAX_FILE_AGE = 86400

    def __init__(self, host_name="localhost", port=11211):
        super().__init__("MEMCACHED", host_name)
        self.host_name = host_name
        self.port = port
        self.client = Client((host_name, port))

    def read_from_cache(self, key:str):
        """
        Gets cached data by key

        Parameters:
        key (str): they key (file) to read

        Returns:
        (json): A JSON object

        """
        data = self.client.get(key)
        return json.loads(data)
        # the cache file does not exist
        # raise an error to catch so the calling program can refresh
        # the data and write it back to the cache
        #raise CacheObjectNotFoundError("Cache object with key '{0}' not found.".format(key))

    def write_to_cache(self, key:str, data:str):
        """
        Takes a JSON object and copies it up to S3

        Parameters:
        key (str): the key (file) name to store

        data (json): the JSON data to store

        """
        self.client.set(key, data, expire=86400)
