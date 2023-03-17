import pytest
import requests
from collections import namedtuple
import random
import string
from src import container_helpers
from src import object_helpers
from src import common_helpers
from src import account_helpers


def pytest_addoption(parser):
    parser.addini('PROJECT_ID', default='', help='project id')
    parser.addini('KEYSTONE_URL', default='', help='keystone url')
    parser.addini('SWIFT_API_URL', default='', help='swift_api_url')
    parser.addini('USERID', default='', help='user id')
    parser.addini('PASSWORD', default='', help='password')


@pytest.fixture(scope="module")
def set_config(request):
    config = {
        'keystone_url': request.config.getini('KEYSTONE_URL'),
        'swift_api_url': request.config.getini('SWIFT_API_URL'),
        'user_id': request.config.getini('USERID'),
        'password': request.config.getini('PASSWORD'),
        'project_id': request.config.getini('PROJECT_ID')
    }
    return config


@pytest.fixture(scope="module")
def get_auth_token(set_config):
    config = set_config
    payload = {
        "auth": {
            "identity": {
                "methods": [
                    "password"
                ],
                "password": {
                    "user": {
                        "id": f"{config.get('user_id')}",
                        "password": f"{config.get('password')}"
                    }
                }
            },
            "scope": {
                "project": {
                    "id": f"{config.get('project_id')}"
                }
            }
        }
    }
    url = f"{config.get('keystone_url')}/tokens"
    response = requests.post(url, json=payload)
    token = response.headers['X-Subject-Token']
    # print(token)
    return token


@pytest.fixture(scope="module")
def get_swift_url(set_config, get_auth_token):
    url = f"{set_config.get('keystone_url')}/catalog"
    headers = {
        "x-auth-token": f"{get_auth_token}"
    }
    response = requests.get(url, headers=headers)
    catalogs = response.json()
    for catalog in catalogs['catalog']:
        if catalog['type'] == 'object-store' and catalog['name'] == 'swift':
            for endpoint in catalog['endpoints']:
                return endpoint["url"]


@pytest.fixture(scope="module")
def random_data():
    random_token = ''.join(random.choices(string.ascii_uppercase + string.digits
                                          + string.ascii_lowercase,
                                          k=random.randint(100, 200)))
    return random_token


@pytest.fixture(scope="module")
def common_request_settings(set_config, get_auth_token, random_data, get_swift_url):
    Settings = namedtuple('Settings', 'url, valid_headers, invalid_headers')
    url = get_swift_url
    valid_headers = get_auth_token
    invalid_headers = random_data
    settings = Settings(url, valid_headers, invalid_headers)
    return settings


@pytest.fixture(scope="function")
def set_query_params(request):
    params = request.param
    return params


@pytest.fixture(scope="function")
def cont_object(common_request_settings, get_auth_token):
    cont_object = object_helpers.ObjectCRUD(
        common_request_settings.url, get_auth_token
    )
    return cont_object


@pytest.fixture(scope="function")
def container(common_request_settings, get_auth_token):

    cont_inst = container_helpers.ContainerCRUD(
        common_request_settings.url, get_auth_token
    )
    return cont_inst


@pytest.fixture(scope="function")
def account(common_request_settings, get_auth_token):

    account_inst = account_helpers.AccountCRUD(
        common_request_settings.url, get_auth_token
    )
    return account_inst


@pytest.fixture(scope="function")
def wipe_account(common_request_settings, get_auth_token):
    token = {
        'x-auth-token': f'{get_auth_token}'
    }
    return common_helpers.wipe_account(common_request_settings.url, token)
