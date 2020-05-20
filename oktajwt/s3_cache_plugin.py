import boto3
import json

from botocore.exceptions import ClientError
from oktajwt.cache_plugin import CachePlugin
from oktajwt.exceptions import CacheObjectNotFoundError

class S3CachePlugin(CachePlugin):

    def __init__(self, bucket_name):
        super().__init__("S3", bucket_name)
        self.s3 = boto3.resource("s3").Bucket(bucket_name)
        json.load_s3 = lambda f: json.load(self.s3.Object(key=f).get()["Body"])
        json.dump_s3 = lambda obj, f: self.s3.Object(key=f).put(Body=json.dumps(obj))

    def read_from_cache(self, key:str):
        """
        Gets cached data by key

        Parameters:
        key (str): they key to fetch

        Returns:
        (json): A JSON object

        """
        try:
            return json.load_s3(key)
        except ClientError:
            # the keys have either expired, or they're not there
            # raise an error to catch so the calling program can refresh
            # the data and write it back to the cache
            raise CacheObjectNotFoundError("Cache object with key '{0}' not found.".format(key))

    def write_to_cache(self, key:str, data:str):
        """
        Takes a JSON object and copies it up to S3

        Parameters:
        key (str): the key name to store

        data (json): the JSON data to store

        """
        json.dump_s3(data, key)
