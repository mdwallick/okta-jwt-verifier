import abc
import json

from abc import ABCMeta, abstractmethod

class CachePlugin(metaclass=ABCMeta):
    @classmethod
    def __subclasshook__(cls, subclass):
        return (hasattr(subclass, 'read_from_cache') and
                callable(subclass.read_from_cache) and
                hasattr(subclass, 'write_to_cache') and
                callable(subclass.write_to_cache) or
                NotImplemented)

    def __init__(self, storage_method, storage_location):
        """
        storage_method: filesystem or S3. More to come.
        storage_location: directory for filesystem, bucket name for S3
        """
        self.storage_method = storage_method
        self.storage_location = storage_location
    
    @abstractmethod
    def read_from_cache(self, key):
        """ Read an object from cache """
        pass

    @abstractmethod
    def write_to_cache(self, key, data):
        """ write some data to cache """
        pass
