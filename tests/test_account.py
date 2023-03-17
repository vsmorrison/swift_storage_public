import pytest
import xml.etree.ElementTree as ET
import time

RESPONSE_HEADERS = [
    'X-Account-Bytes-Used', 'X-Account-Container-Count', 'X-Account-Object-Count',
    'x-account-storage-policy-cold-bytes-used',
    'X-Timestamp', 'X-Trans-Id', 'x-openstack-request-id', 
    'x-account-storage-policy-cold-container-count', 
    'x-account-storage-policy-cold-object-count',
    'X-Account-Storage-Policy-Policy-0-Bytes-Used',
    'X-Account-Storage-Policy-Policy-0-Container-Count',
    'X-Account-Storage-Policy-Policy-0-Object-Count',
]


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['format=json'], indirect=True)
def test_get_account_listing(container, set_query_params, account):
    containers = [f'{name}' for name in range(10)]
    for cont_name in containers:
        container.create_container(cont_name=cont_name)
    response = account.get_account(query=set_query_params)
    assert response.status_code == 200
    listing = response.json()
    for container in listing:
        assert container['name'] in containers


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params',
                         ['format=json&marker=1&end_marker=4'],
                         indirect=True)
def test_account_listing_range(container, set_query_params, account):
    containers = [f'{name}' for name in range(10)]
    for cont_name in containers:
        container.create_container(cont_name=cont_name)
    response = account.get_account(query=set_query_params)
    listing = response.json()
    assert response.status_code == 200
    for container in listing:
        assert container['name'] in [f'{name}' for name in range(1, 4)]


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params',
                         ['format=json&marker=0&end_marker=5&prefix=1'],
                         indirect=True)
def test_account_listing_prefix_range(container, set_query_params, account):
    containers = [f'{name*5}' for name in range(5)]
    for cont_name in containers:
        container.create_container(cont_name=cont_name)
    response = account.get_account(query=set_query_params)
    listing = response.json()
    assert response.status_code == 200
    for container in listing:
        assert container['name'] in ['10', '15']


@pytest.mark.usefixtures('wipe_account')
# @pytest.mark.parametrize('set_query_params', ['&delimiter=/&prefix=aaa'])
def test_account_listing_delimiter_prefix(container, cont_object, account):
    cont_name = 'delimiter_prefix'
    container.create_container(cont_name=cont_name)
    directories = ['aaa/', 'bbb/']
    for directory in directories:
        cont_object.create_object(obj_name=directory)
        listing = [f'{cont_name}/{directory}{name}' for name in range(5)]
        for obj_name in listing:
            response = cont_object.create_object(obj_name=obj_name)
            assert response.status_code == 201
    get_resp = account.get_account()
    resp_listing = get_resp.json()
    print(resp_listing)
    # assert len(resp_listing) == 1

@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['format=plain'], indirect=True)
def test_get_account_plain(container, set_query_params, account):
    containers = [f'{name}' for name in range(5)]
    for cont_name in containers:
        container.create_container(cont_name=cont_name)
    response = account.get_account(query=set_query_params)
    assert response.status_code == 200
    listing = response.text
    assert listing == '0\n1\n2\n3\n4\n'


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['format=xml'], indirect=True)
def test_get_account_xml(container, set_query_params, account):
    containers = [f'{name}' for name in range(5)]
    for cont_name in containers:
        container.create_container(cont_name=cont_name)
    response = account.get_account(query=set_query_params)
    assert response.status_code == 200
    root = ET.fromstring(response.text)
    for child in root:
        assert child.tag == 'container'
        for nested_child in child:
            assert nested_child.tag in [
                'bytes', 'count', 'name', 'last_modified',
                'storage_policy_index'
            ]
    for name in root.findall('name'):
        assert name.find('name') in containers


@pytest.mark.usefixtures('wipe_account')
def test_create_account_meta(account):
    meta_headers = {
        'x-account-meta-create': 'create',
    }
    delete_headers = {
        'x-account-meta-create': ''
    }
    response = account.post_metadata(headers=meta_headers)
    assert response.status_code == 204
    resp_headers = account.head_account().headers
    meta_keys = list(meta_headers.keys())
    meta_values = list(meta_headers.values())
    for index, header_key in enumerate(meta_keys):
        assert header_key in resp_headers
        assert meta_values[index] in resp_headers[header_key]
    account.post_metadata(headers=delete_headers)


@pytest.mark.usefixtures('wipe_account')
def test_update_account_meta(account):
    meta_headers = {
        'x-account-meta-create': 'create',
    }
    response = account.post_metadata(headers=meta_headers)
    assert response.status_code == 204
    resp_headers = account.head_account().headers
    meta_keys = list(meta_headers.keys())
    meta_values = list(meta_headers.values())
    for index, header_key in enumerate(meta_keys):
        assert header_key in resp_headers
        assert meta_values[index] in resp_headers[header_key]
    updated_headers = {
        'x-account-meta-create': 'create_updated'
    }
    upd_response = account.post_metadata(headers=updated_headers)
    assert upd_response.status_code == 204
    upd_resp_headers = account.head_account().headers
    upd_meta_keys = list(updated_headers.keys())
    upd_meta_values = list(updated_headers.values())
    for index, header_key in enumerate(upd_meta_keys):
        assert header_key in upd_resp_headers
        assert upd_meta_values[index] in upd_resp_headers[header_key]


@pytest.mark.usefixtures('wipe_account')
def test_delete_account_meta(account):
    meta_headers = {
        'x-account-meta-delete': 'delete',
    }
    response = account.post_metadata(headers=meta_headers)
    assert response.status_code == 204
    resp_headers = account.head_account().headers
    meta_keys = list(meta_headers.keys())
    meta_values = list(meta_headers.values())
    for index, header_key in enumerate(meta_keys):
        assert header_key in resp_headers
        assert meta_values[index] in resp_headers[header_key]
    delete_headers = {
        'x-account-meta-delete': ''
    }
    del_response = account.post_metadata(headers=delete_headers)
    assert del_response.status_code == 204
    del_resp_headers = account.head_account().headers
    for header in list(delete_headers.keys()):
        assert header not in del_resp_headers


@pytest.mark.usefixtures('wipe_account')
def test_delete_account_meta_x_remove(account):
    meta_headers = {
        'x-account-meta-delete': 'delete',
    }
    response = account.post_metadata(headers=meta_headers)
    assert response.status_code == 204
    resp_headers = account.head_account().headers
    meta_keys = list(meta_headers.keys())
    meta_values = list(meta_headers.values())
    for index, header_key in enumerate(meta_keys):
        assert header_key in resp_headers
        assert meta_values[index] in resp_headers[header_key]
    delete_headers = {
        'x-remove-account-meta-delete': 'delete'
    }
    del_response = account.post_metadata(headers=delete_headers)
    assert del_response.status_code == 204
    del_resp_headers = account.head_account().headers
    for header in list(delete_headers.keys()):
        assert header not in del_resp_headers


@pytest.mark.xfail(reason='returns 204 not 400')
@pytest.mark.usefixtures('wipe_account')
def test_account_empty_meta_key(account):
    meta_headers = {
        'x-account-meta-': 'metatest_e',
    }
    response = account.post_metadata(headers=meta_headers)
    assert response.status_code == 400


# work on >=256
@pytest.mark.usefixtures('wipe_account')
def test_account_long_meta_key(account):
    long_value = 'a'*241
    meta_headers = {
        f'x-account-meta-{long_value}': 'metatest_l',
    }
    response = account.post_metadata(headers=meta_headers)
    assert response.status_code == 400


# works on 4073 value, max value should be 256
@pytest.mark.xfail(reason='returns 500 not 400, value is more than 256')
@pytest.mark.usefixtures('wipe_account')
def test_account_long_meta_value(account):
    long_value = 'a'*4073
    meta_headers = {
        'x-account-meta-test': f'{long_value}'
    }
    response = account.post_metadata(headers=meta_headers)
    assert response.status_code == 400


#according to doc limit is 90 meta headers
@pytest.mark.usefixtures('wipe_account')
@pytest.mark.xfail(reason='unknown value limit, returns 500 not 400')
def test_account_metadata_count_limit(account):
    keys = [f'x-account-meta-test{key}' for key in range(91)]
    values = [f'{num}' for num in range(len(keys))]
    delete_values = ['' for i in range(len(keys))]
    meta_headers = dict(zip(keys, values))
    delete_headers = dict(zip(keys, delete_values))
    response = account.post_metadata(headers=meta_headers)
    assert response.status_code == 400
    # need finalization
    account.post_metadata(headers=delete_headers)


# according to doc limit is 4096 bytes
@pytest.mark.usefixtures('wipe_account')
@pytest.mark.xfail(reason='returns 500 not 400')
def test_account_metadata_bytes_limit(account):
    keys = [f'x-account-meta-test{key}' for key in range(16)]
    values = ['a'*256 for i in range(len(keys))]
    delete_values = ['' for i in range(len(keys))]
    meta_headers = dict(zip(keys, values))
    delete_headers = dict(zip(keys, delete_values))
    response = account.post_metadata(headers=meta_headers)
    print(response.status_code)
    assert response.status_code == 400
    # need finalization
    account.post_metadata(headers=delete_headers)

@pytest.mark.usefixtures('wipe_account')
def test_account_empty_stats(account):
    response = account.head_account()
    assert response.status_code == 204
    resp_headers = dict(response.headers)
    assert resp_headers['X-Account-Bytes-Used'] == '0'
    assert resp_headers['X-Account-Container-Count'] == '0'
    assert resp_headers['X-Account-Object-Count'] == '0'
    assert resp_headers['x-account-storage-policy-cold-bytes-used'] == '0'
    assert resp_headers['x-account-storage-policy-cold-container-count'] == '0'
    assert resp_headers['x-account-storage-policy-cold-object-count'] == '0'
    assert resp_headers['X-Account-Storage-Policy-Policy-0-Bytes-Used'] == '0'
    assert resp_headers[
               'X-Account-Storage-Policy-Policy-0-Container-Count'] == '0'
    assert resp_headers['X-Account-Storage-Policy-Policy-0-Object-Count'] == '0'
    get_resp = account.get_account()
    listing = get_resp.json()
    assert not listing


@pytest.mark.usefixtures('wipe_account')
def test_account_nonempty_stats(account, container, cont_object):
    cont_names = ['test', 'test1']
    for cont_name in cont_names:
        container.create_container(cont_name=cont_name)
    obj_names = ['test/1', 'test/2', 'test/3']
    for name in obj_names:
        cont_object.create_object(obj_name=name)
    time.sleep(5)
    response = account.head_account()
    assert response.status_code == 204
    resp_headers = dict(response.headers)
    assert resp_headers['X-Account-Container-Count'] == '2'
    assert resp_headers['X-Account-Object-Count'] == '3'
    assert resp_headers[
               'X-Account-Storage-Policy-Policy-0-Container-Count'] == '2'
    assert resp_headers['X-Account-Storage-Policy-Policy-0-Object-Count'] == '3'
    get_resp = account.get_account()
    listing = get_resp.json()
    assert listing


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['bulk-delete'])
def test_bulk_delete(account, container, cont_object, set_query_params):
    cont_names = ['test', 'test1']
    for cont_name in cont_names:
        container.create_container(cont_name=cont_name)
    obj_names = ['test/1', 'test/2', 'test/3']
    for name in obj_names:
        cont_object.create_object(obj_name=name)
    headers = {
        'Content-Type': 'text/plain'
    }
    objects_to_delete = ['test/3', 'test1']
    response = account.post_metadata(
        headers=headers, query=set_query_params,
        payload='\n'.join(objects_to_delete)
    )
    cont_listing = account.get_account().json()
    for name in cont_listing:
        assert name['name'] not in objects_to_delete
    # need obj assertion mb


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['bulk-delete'])
def test_bulk_delete_accept_plain(account, container, cont_object, set_query_params):
    cont_names = ['plain', 'plain1']
    for cont_name in cont_names:
        container.create_container(cont_name=cont_name)
    obj_names = ['plain/1', 'plain/2', 'plain/3']
    for name in obj_names:
        cont_object.create_object(obj_name=name)
    headers = {
        'Content-Type': 'text/plain',
        'Accept': 'text/plain'
    }
    objects_to_delete = ['plain/3', 'plain1']
    response = account.post_metadata(
        headers=headers, query=set_query_params,
        payload='\n'.join(objects_to_delete)
    )
    bulk_delete_resp = response.text.split('\n')
    assert bulk_delete_resp[0] == 'Number Deleted: 2'


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['bulk-delete'])
def test_bulk_delete_accept_json(account, container, cont_object, set_query_params):
    cont_names = ['json', 'json1']
    for cont_name in cont_names:
        container.create_container(cont_name=cont_name)
    obj_names = ['json/1', 'json/2', 'json/3']
    for name in obj_names:
        cont_object.create_object(obj_name=name)
    headers = {
        'Content-Type': 'text/plain',
        'Accept': 'application/json'
    }
    objects_to_delete = ['json/3', 'json1']
    response = account.post_metadata(
        headers=headers, query=set_query_params,
        payload='\n'.join(objects_to_delete)
    )
    assert response.json()['Number Deleted'] == 2


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['bulk-delete'])
def test_bulk_delete_accept_xml(account, container, cont_object, set_query_params):
    cont_names = ['xml', 'xml1']
    for cont_name in cont_names:
        container.create_container(cont_name=cont_name)
    obj_names = ['xml/1', 'xml/2', 'xml/3']
    for name in obj_names:
        cont_object.create_object(obj_name=name)
    headers = {
        'Content-Type': 'text/plain',
        'Accept': 'application/xml'
    }
    objects_to_delete = ['xml/3', 'xml1']
    response = account.post_metadata(
        headers=headers, query=set_query_params,
        payload='\n'.join(objects_to_delete)
    )
    root = ET.fromstring(response.text)
    assert root.tag == 'delete'
    for child in root:
        assert child.tag in [
            'number_not_found', 'response_status', 'response_body',
            'number_deleted'
        ]
    assert root.find('number_deleted').text == 2


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['bulk-delete'])
def test_bulk_delete_wrong_content_type(account, container, cont_object, set_query_params):
    cont_names = ['test', 'test1']
    for cont_name in cont_names:
        container.create_container(cont_name=cont_name)
    obj_names = ['test/1', 'test/2', 'test/3']
    for name in obj_names:
        cont_object.create_object(obj_name=name)
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/xml'
    }
    objects_to_delete = {
        'test': 'test1'
    }
    response = account.post_metadata(
        headers=headers, query=set_query_params,
        payload=objects_to_delete
    )
    assert response.status_code == 400


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['bulk-delete'])
def test_account_delete_bulk_input_name_length_limit(account, container, cont_object, set_query_params):
    cont_names = ['test', 'test1']
    for cont_name in cont_names:
        container.create_container(cont_name=cont_name)
    obj_names = [f'test/{name}' for name in range(10)]
    for name in obj_names:
        cont_object.create_object(obj_name=name)
    headers = {
        'Content-Type': 'text/plain',
        'Accept': 'application/xml'
    }
    name = 'a'
    objects_to_delete = [f'test/{name*1966}']
    response = account.post_metadata(
        headers=headers, query=set_query_params,
        payload='\n'.join(objects_to_delete)
    )
    response_status = response.json()['Response Status']
    # assert response.status_code == 400
    assert response_status == '400 Bad Request'


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['bulk-delete'])
def test_account_delete_bulk_input_limit(account, container, cont_object, set_query_params):
    cont_names = ['test', 'test1']
    for cont_name in cont_names:
        container.create_container(cont_name=cont_name)
    obj_names = [f'test/{name}' for name in range(5)]
    for name in obj_names:
        cont_object.create_object(obj_name=name)
    headers = {
        'Content-Type': 'text/plain',
        'Accept': 'application/xml'
    }
    objects_to_delete = [f'test/{name}' for name in range(10001)]
    response = account.post_metadata(
        headers=headers, query=set_query_params,
        payload='\n'.join(objects_to_delete)
    )
    response_status = response.json()['Response Status']
    # assert response.status_code == 400
    assert response_status == '400 Bad Request'


@pytest.mark.usefixtures('wipe_account')
def test_account_stats_storage_policy(account, container, cont_object):
    cold_header = {
        'x-storage-policy': 'cold'
    }
    cold_cont_names = ['cold', 'cold1']
    default_policy_cont_names = ['private', 'private1']
    for cont_name in cold_cont_names:
        container.create_container(cont_name=cont_name, headers=cold_header)
    for cont_name in default_policy_cont_names:
        container.create_container(cont_name=cont_name)
    cold_obj_names = [f'cold/{name}' for name in range(5)]
    default_policy_obj_names = [f'private/{name}' for name in range(3)]
    for name in cold_obj_names:
        cont_object.create_object(obj_name=name)
    for name in default_policy_obj_names:
        cont_object.create_object(obj_name=name)
    time.sleep(10)
    response = account.head_account()
    resp_headers = dict(response.headers)
    print(resp_headers)
    assert resp_headers['X-Account-Container-Count'] == str(len(cold_cont_names) + len(default_policy_cont_names))
    assert resp_headers['x-account-storage-policy-cold-container-count'] == str(len(cold_cont_names))
    assert resp_headers['X-Account-Storage-Policy-Policy-0-Container-Count'] == str(len(default_policy_cont_names))
    assert resp_headers['x-account-storage-policy-cold-object-count'] == str(len(cold_obj_names))
    assert resp_headers['X-Account-Storage-Policy-Policy-0-Object-Count'] == str(len(default_policy_obj_names))


@pytest.mark.usefixtures('wipe_account')
def test_account_pagination(container, account):
    cont_listing = [f'{cont_name:05}' for cont_name in range(11010)]
    for name in cont_listing:
        response = container.create_container(cont_name=name)
        assert response.status_code == 201
    get_resp = account.get_account_listing()
    resp_listing = get_resp[1]
    assert len(resp_listing) == 11010
    for cont_name in resp_listing:
        assert cont_name['name'] in cont_listing
    # working need watching


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['format=json&prefix=1'])
def test_account_prefix_pagination(container, account, set_query_params):
    cont_listing = [f'{cont_name:05}' for cont_name in range(11010)]
    for name in cont_listing:
        response = container.create_container(cont_name=name)
        assert response.status_code == 201
    get_resp = account.get_account(query=set_query_params)
    resp_listing = get_resp.json()
    assert len(resp_listing) == 1011
    for cont_name in resp_listing:
        assert cont_name['name'] in [f'{name:05}' for name in range(10000, 11011)]
    # working need watching


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['format=json'])
def test_account_prefix_pagination(container, account, set_query_params):
    cont_listing = [f'{cont_name:05}' for cont_name in range(20)]
    for name in cont_listing:
        response = container.create_container(cont_name=name)
        assert response.status_code == 201
    get_resp = account.get_account(query=set_query_params)
    resp_listing = get_resp.json()
    assert len(resp_listing) == 1011
    for cont_name in resp_listing:
        assert cont_name['name'] in [f'{name:05}' for name in range(10000, 11011)]


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['format=json&delimiter=/'])
def test_account_listing_delimiter(container, set_query_params, cont_object, account):
    cont_name = ['test', 'test1']
    listing = [f'{cont_name[0]}/{name}' for name in range(5)]
    for name in cont_name:
        container.create_container(cont_name=name)
    for obj_name in listing:
        cont_object.create_object(obj_name=obj_name)
    get_resp = account.get_account(query=set_query_params)
    resp_listing = get_resp.json()
    assert len(resp_listing) == 2


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['format=json&prefix=0000/&delimiter=/'])
def test_account_listing_prefix_delimiter(container, set_query_params, cont_object, account):
    cont_name = ['test', 'test1']
    listing = [f'{cont_name[0]}/{name}' for name in range(11000)]
    for name in cont_name:
        container.create_container(cont_name=name)
    for obj_name in listing:
        cont_object.create_object(obj_name=obj_name)
    get_resp = account.get_account(query=set_query_params)
    resp_listing = get_resp.json()
    assert len(resp_listing) == 0
    # working need watching


