import requests
import re


class AccountCRUD:

    def __init__(self, base_url, token=None):
        self.base_url = base_url
        self.token = token

    def get_account_listing(self, query='format=json'):
        default_headers = {
            'x-auth-token': self.token
        }
        url = f"{self.base_url}"
        default_query = query
        account_headers = self.head_account()
        listing_to_return = []

        while True:
            response = requests.get(url, headers=default_headers, params=query)
            query = default_query
            resp_listing = response.json()
            if not resp_listing:
                return account_headers, listing_to_return
            for obj in resp_listing:
                listing_to_return.append(obj)
            last_element = resp_listing[-1]["name"]
            if 'marker=' in query:
                query = re.sub(r'(&marker=\d+)', '', query)
            query = f"{query}&marker={last_element}"

    def get_account(self, query='format=json', headers=None):
        default_headers = {
            'x-auth-token': self.token
        }
        url = f"{self.base_url}"
        if headers:
            default_headers.update(headers)
        response = requests.get(url, headers=default_headers, params=query)
        return response

    def head_account(self, headers=None):
        default_headers = {
            'x-auth-token': self.token
        }
        url = f"{self.base_url}"
        if headers:
            default_headers.update(headers)
        response = requests.head(url, headers=default_headers)
        return response

    def post_metadata(self, headers=None, query=None, payload=None):
        default_headers = {
            'x-auth-token': self.token
        }
        url = f"{self.base_url}"
        if headers:
            default_headers.update(headers)
        response = requests.post(
            url=url, headers=default_headers, params=query, data=payload
        )
        return response
