import json
import requests

class Http:
    DEFAULT_HEADERS = {
        "Accept": "application/json"
    }

    OAUTH_HEADERS = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    @staticmethod
    def execute_get(url, headers=DEFAULT_HEADERS):
        rest_response = requests.get(url, headers=headers)
        return Http.handle_response_as_json(rest_response)

    @staticmethod
    def execute_post(url, body=None, headers=DEFAULT_HEADERS):
        rest_response = requests.post(url, headers=headers, json=body)
        return Http.handle_response_as_json(rest_response)

    @staticmethod
    def execute_put(url, body=None, headers=DEFAULT_HEADERS):
        rest_response = requests.put(url, headers=headers, json=body)
        return Http.handle_response_as_json(rest_response)

    @staticmethod
    def execute_delete(url, headers=DEFAULT_HEADERS):
        rest_response = requests.delete(url, headers=headers)
        return Http.handle_response_as_json(rest_response)

    @staticmethod
    def handle_response_as_json(rest_response):
        try:
            response_json = rest_response.json()
        except Exception:
            response_json = {"status": "none"}

        return response_json