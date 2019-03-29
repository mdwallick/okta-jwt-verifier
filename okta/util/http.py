import requests
import json

# TODO - check for a JSON or empty response body, likely for post/put/delete

class Http:
    DEFAULT_HEADERS = {
        "Accept": "application/json"
    }

    @staticmethod
    def execute_post(url, body=None, headers=DEFAULT_HEADERS):
        rest_response = requests.post(url, headers=headers, json=body)
        response_json = rest_response.json()

        # print json.dumps(response_json, indent=4, sort_keys=True)
        return response_json

    @staticmethod
    def execute_put(url, body=None, headers=DEFAULT_HEADERS):
        rest_response = requests.put(url, headers=headers, json=body)
        response_json = rest_response.json()

        # print json.dumps(response_json, indent=4, sort_keys=True)
        return response_json

    @staticmethod
    def execute_delete(url, headers=DEFAULT_HEADERS):
        rest_response = requests.delete(url, headers=headers)
        try:
            response_json = rest_response.json()
        except:
            response_json = { "status": "none" }

        # print json.dumps(response_json, indent=4, sort_keys=True)
        return response_json

    @staticmethod
    def execute_get(url, headers=DEFAULT_HEADERS):
        print("execute_get({0})".format(url))
        rest_response = requests.get(url, headers=headers)
        response_json = rest_response.json()

        # print json.dumps(response_json, indent=4, sort_keys=True)
        return response_json
