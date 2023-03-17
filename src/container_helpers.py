import requests
import re


class ContainerCRUD:

    def __init__(self, base_url, token=None):
        self.base_url = base_url
        self.token = token

    def create_container(self, headers=None, cont_name=None):
        default_headers = {
            'x-auth-token': self.token
        }
        url = f"{self.base_url}/{cont_name}"
        if headers:
            default_headers.update(headers)
        response = requests.put(url, headers=default_headers)
        return response

    def delete_container(self, headers=None, cont_name=None):
        default_headers = {
            'x-auth-token': self.token
        }
        url = f"{self.base_url}/{cont_name}"
        if headers:
            default_headers.update(headers)
        response = requests.delete(url, headers=default_headers)
        return response

    def get_container_listing(self, query=None, headers=None, cont_name=None):
        default_headers = {
            'x-auth-token': self.token
        }
        url = f"{self.base_url}/{cont_name}"
        if headers:
            default_headers.update(headers)
        default_query = query
        container_headers = self.head_container()
        listing_to_return = []

        while True:
            response = requests.get(url, headers=default_headers, params=query)
            query = default_query
            resp_listing = response.json()
            if not resp_listing:
                return container_headers, listing_to_return
            for obj in resp_listing:
                listing_to_return.append(obj)
            last_element = resp_listing[-1]["name"]
            if 'marker=' in query:
                query = re.sub(r'(&marker=\d+)', '', query)
            query = f"{query}&marker={last_element}"

    def get_container(self, query=None, headers=None, cont_name=None):
        default_headers = {
            'x-auth-token': self.token
        }
        url = f"{self.base_url}/{cont_name}"
        if headers:
            default_headers.update(headers)
        response = requests.get(url, headers=default_headers, params=query)
        return response

    def head_container(self, headers=None, cont_name=None):
        default_headers = {
            'x-auth-token': self.token
        }
        url = f"{self.base_url}/{cont_name}"
        if headers:
            default_headers.update(headers)
        response = requests.head(url, headers=default_headers)
        return response

    def create_container_metadata(self, headers=None, cont_name=None):
        default_headers = {
            'x-auth-token': self.token
        }
        url = f"{self.base_url}/{cont_name}"
        if headers:
            default_headers.update(headers)
        response = requests.post(url, headers=default_headers)
        return response

    def get_acc_containers(self, query=None, headers=None):
        default_headers = {
            'x-auth-token': self.token
        }
        url = f"{self.base_url}"
        if headers:
            default_headers.update(headers)
        response = requests.get(url, headers=default_headers, params=query)
        return response

    def head_acc_containers(self, headers=None):
        default_headers = {
            'x-auth-token': self.token
        }
        url = f"{self.base_url}"
        if headers:
            default_headers.update(headers)
        response = requests.head(url, headers=default_headers)
        return response

