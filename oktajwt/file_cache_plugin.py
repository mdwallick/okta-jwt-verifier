import json
import os
import time
import traceback

from oktajwt.cache_plugin import CachePlugin
from oktajwt.exceptions import CacheObjectNotFoundError

class FileCachePlugin(CachePlugin):

    MAX_FILE_AGE = 86400

    def __init__(self, cache_directory):
        super().__init__("FILE", cache_directory)
        
        try:
            if not os.path.isdir(cache_directory):
                # create the cache directory if it doesn't exist
                os.mkdir(cache_directory)
        except FileNotFoundError as e:
            stack_trace = traceback.format_exc()
            print("Exception: {0}".format(e))
            print(stack_trace)
            exit(2)

    def read_from_cache(self, key:str):
        """
        Gets cached data by key

        Parameters:
        key (str): they key (file) to read

        Returns:
        (json): A JSON object

        """
        try:
            filename = "{0}/{1}".format(self.storage_location, key)
            file_age = self.__get_file_age(filename)

            if file_age > self.MAX_FILE_AGE:
                raise CacheObjectNotFoundError("Cache object with key '{0}' not found.".format(key))
            else:
                with open(filename, "r") as infile:
                    data = json.load(infile)
                return data
        except IOError:
            # the cache file does not exist
            # raise an error to catch so the calling program can refresh
            # the data and write it back to the cache
            raise CacheObjectNotFoundError("Cache object with key '{0}' not found.".format(key))

    def write_to_cache(self, key:str, data:str):
        """
        Takes a JSON object and copies it up to S3

        Parameters:
        key (str): the key (file) name to store

        data (json): the JSON data to store

        """
        filename = "{0}/{1}".format(self.storage_location, key)
        with open(filename, "w") as outfile:
            json.dump(data, outfile)

    def __get_file_age(self, filepath):
        age = time.time() - os.path.getmtime(filepath)
        #logging.debug("File is {0} seconds old".format(age))
        return age