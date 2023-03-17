import requests


class ObjectCRUD:

    def __init__(self, base_url, token=None):
        self.base_url = base_url
        self.token = token

    def create_object(self, headers=None, obj_name=None):
        default_headers = {
            'x-auth-token': self.token
        }
        url = f"{self.base_url}/{obj_name}"
        if headers:
            default_headers.update(headers)
        response = requests.put(url, headers=default_headers)
        return response

    def delete_object(self, headers=None, obj_name=None):
        default_headers = {
            'x-auth-token': self.token
        }
        url = f"{self.base_url}/{obj_name}"
        if headers:
            default_headers.update(headers)
        response = requests.delete(url, headers=default_headers)
        return response
