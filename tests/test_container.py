import time
import xml.etree.ElementTree as ET
import pytest


@pytest.mark.usefixtures('wipe_account')
def test_create_nometa_container(container):
    cont_name = 'nometa'
    template_headers = [
        'x-openstack-request-id', 'X-Trans-Id', 'Content-Length', 'Date',
        'X-Timestamp'
    ]
    response = container.create_container(cont_name=cont_name)
    assert response.status_code == 201
    for header in response.headers:
        assert header in template_headers


@pytest.mark.usefixtures('wipe_account')
def test_create_segments_container(container):
    parent_headers = {
        'x-storage-policy': 'cold'
    }
    parent_cont = 'parent'
    container.create_container(headers=parent_headers, cont_name=parent_cont)
    parent_resp_headers = dict(
        container.head_container(headers=parent_headers,
                                 cont_name=parent_cont).headers
    )
    child_cont = 'parent_segments'
    response = container.create_container(cont_name=child_cont)
    assert response.status_code == 201
    child_resp_headers = dict(
        container.head_container(cont_name=child_cont).headers)
    assert child_resp_headers['x-storage-policy'] == parent_resp_headers['x-storage-policy']


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.xfail(reason='response status code is 404')
def test_create_container_with_slash(container):
    cont_name = '12/3'
    response = container.create_container(cont_name=cont_name)
    assert response.status_code == 400


# works on >256
@pytest.mark.usefixtures('wipe_account')
def test_create_container_with_long_name(container):
    cont_name = 'a'*257
    response = container.create_container(cont_name=cont_name)
    assert response.status_code == 400


@pytest.mark.usefixtures('wipe_account')
def test_create_container_not_utf8(container):
    cont_name = '\udcbe\udcd0\udcb1'
    response = container.create_container(cont_name=cont_name)
    assert response.status_code == 400


@pytest.mark.usefixtures('wipe_account')
def test_successful_create_over_existing(container):
    cont_name = 'existing'
    container.create_container(cont_name=cont_name)
    response = container.create_container(cont_name=cont_name)
    assert response.status_code == 201


@pytest.mark.usefixtures('wipe_account')
def test_delete_container(container):
    cont_name = '123'
    template_headers = [
        'x-openstack-request-id', 'X-Trans-Id', 'Content-Length', 'Date',
        'X-Timestamp', 'x-container-storage-policy-index', 'Content-Type',
        'x-container-storage-policy-name'
    ]
    container.create_container(cont_name=cont_name)
    response = container.delete_container(cont_name=cont_name)
    assert response.status_code == 204
    for header in response.headers:
        assert header in template_headers


@pytest.mark.usefixtures('wipe_account')
def test_delete_nonempty_container(container, cont_object):
    cont_name = 'nonempty'
    container.create_container(cont_name=cont_name)
    for obj_name in [f'{cont_name}/{obj}' for obj in range(2)]:
        cont_object.create_object(obj_name=obj_name)
    response = container.delete_container(cont_name=cont_name)
    assert response.status_code == 409


@pytest.mark.usefixtures('wipe_account')
def test_delete_noexistent_container(container):
    cont_name = 'noexist'
    response = container.delete_container(cont_name=cont_name)
    assert response.status_code == 404


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['format=json'], indirect=True)
def test_get_noexistent_container(container, set_query_params):
    cont_name = 'noexist'
    response = container.get_container(
        query=set_query_params, cont_name=cont_name
    )
    assert response.status_code == 404


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['format=json'], indirect=True)
def test_get_container(container, set_query_params, cont_object):
    cont_name = '123'
    template_headers = [
        'Accept-Ranges', 'X-Container-Bytes-Used', 'X-Container-Object-Count',
        'x-container-storage-policy-index', 'x-container-storage-policy-name',
        'x-openstack-request-id', 'x-storage-policy', 'X-Timestamp', 'X-Trans-Id',
        'Date', 'Content-Length', 'Content-Type', 'X-Container-Meta-Type'
    ]
    container.create_container(cont_name=cont_name)
    for obj_name in [f'{cont_name}/{obj}' for obj in range(2)]:
        cont_object.create_object(obj_name=obj_name)
    response = container.get_container(
        query=set_query_params, cont_name=cont_name
    )
    assert response.status_code == 200
    for header in response.headers:
        assert header in template_headers
    listing = response.json()
    for obj in listing:
        assert obj['name'] in ['0', '1']


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['format=xml'], indirect=True)
def test_get_container_xml(container, set_query_params, cont_object):
    cont_name = 'xml'
    listing = [f'{cont_name}/{obj}' for obj in range(2)]
    container.create_container(cont_name=cont_name)
    for obj_name in listing:
        cont_object.create_object(obj_name=obj_name)
    response = container.get_container(
        query=set_query_params, cont_name=cont_name
    )
    assert response.status_code == 200
    root = ET.fromstring(response.text)
    for child in root:
        assert child.tag == 'object'
        for nested_child in child:
            assert nested_child.tag in [
                'name', 'content_type', 'bytes', 'hash', 'last_modified',
                'subdir'
            ]
    for name in root.findall('name'):
        assert name.find('name') in listing


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['format=plain'], indirect=True)
def test_get_container_plain(container, set_query_params, cont_object):
    cont_name = 'plain'
    container.create_container(cont_name=cont_name)
    for obj_name in [f'{cont_name}/{obj}' for obj in range(2)]:
        cont_object.create_object(obj_name=obj_name)
    response = container.get_container(
        query=set_query_params, cont_name=cont_name
    )
    listing = response.text
    assert response.status_code == 200
    assert listing == '0\n1\n'


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.xfail(reason='document says should be 204 code')
@pytest.mark.parametrize('set_query_params', ['format=json'], indirect=True)
def test_get_empty_container_listing(container, set_query_params):
    cont_name = 'empty'
    container.create_container(cont_name=cont_name)
    response = container.get_container(
        query=set_query_params, cont_name=cont_name
    )
    assert response.status_code == 200
    listing = response.json()
    assert not listing


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['format=json'], indirect=True)
def test_head_container_with_meta(container, set_query_params):
    headers_with_meta = {
        'x-container-meta-test': 'metatest',
        'x-container-meta-test2': 'test2'
    }
    cont_name = 'meta1'
    container.create_container(headers=headers_with_meta, cont_name=cont_name)
    response = container.head_container(cont_name=cont_name)
    assert response.status_code == 204
    resp_headers = response.headers
    meta_keys = list(headers_with_meta.keys())
    meta_values = list(headers_with_meta.values())
    for index, header_key in enumerate(meta_keys):
        assert header_key in resp_headers
        assert meta_values[index] in resp_headers[header_key]


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['format=json'], indirect=True)
def test_create_container_meta(container, set_query_params):
    cont_name = 'meta_c'
    template_headers = [
        'Accept-Ranges', 'X-Container-Bytes-Used', 'X-Container-Meta-Type',
        'X-Container-Object-Count', 'x-container-storage-policy-index',
        'x-container-storage-policy-name', 'x-openstack-request-id',
        'x-storage-policy', 'X-Timestamp', 'X-Trans-Id', 'Date'
    ]
    container.create_container(cont_name=cont_name)
    headers_with_meta = {
        'x-container-meta-metatest': 'metatest_c',
        'x-container-meta-create': 'create2'
    }
    response = container.create_container_metadata(
        headers=headers_with_meta, cont_name=cont_name
    )
    assert response.status_code == 204
    for header in response.headers:
        assert header in template_headers
    head_response = container.head_container(cont_name=cont_name)
    assert head_response.status_code == 204
    resp_headers = head_response.headers
    meta_keys = list(headers_with_meta.keys())
    meta_values = list(headers_with_meta.values())
    for index, header_key in enumerate(meta_keys):
        assert header_key in resp_headers
        assert meta_values[index] in resp_headers[header_key]


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['format=json'], indirect=True)
def test_update_containers_meta(container, set_query_params):
    headers_with_meta = {
        'x-container-meta-metatest': 'metatest',
        'x-container-meta-create': 'create2'
    }
    cont_name = 'meta_u'
    container.create_container(headers=headers_with_meta, cont_name=cont_name)
    headers_with_meta_updated = {
        'x-container-meta-metatest': 'metatest_u',
        'x-container-meta-create': 'create3'
    }
    response = container.create_container_metadata(
        headers=headers_with_meta_updated, cont_name=cont_name
    )
    assert response.status_code == 204
    head_response = container.head_container(cont_name=cont_name)
    assert head_response.status_code == 204
    resp_headers = head_response.headers
    meta_keys = list(headers_with_meta_updated.keys())
    meta_values = list(headers_with_meta_updated.values())
    for index, header_key in enumerate(meta_keys):
        assert header_key in resp_headers
        assert meta_values[index] in resp_headers[header_key]


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['format=json'], indirect=True)
def test_delete_containers_meta(container, set_query_params):
    headers_with_meta = {
        'x-container-meta-metatest': 'metatest',
        'x-container-meta-create': 'create2',
        'x-container-meta-check': 'check'
    }
    cont_name = 'meta_d'
    container.create_container(headers=headers_with_meta, cont_name=cont_name)
    headers_with_meta_to_delete = {
        'x-container-meta-metatest': '',
        'x-remove-container-meta-create': 'x'
    }
    response = container.create_container_metadata(
        headers=headers_with_meta_to_delete, cont_name=cont_name
    )
    assert response.status_code == 204
    head_response = container.head_container(cont_name=cont_name)
    assert head_response.status_code == 204
    resp_headers = head_response.headers
    for header in list(headers_with_meta_to_delete.keys()):
        assert header not in resp_headers


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.xfail(reason='returns 204 not 400')
def test_create_container_empty_meta_key(container):
    cont_name = 'meta_e'
    container.create_container(cont_name=cont_name)
    meta_headers = {
        'x-container-meta-': 'metatest_e',
    }
    response = container.create_container_metadata(
        headers=meta_headers, cont_name=cont_name
    )
    assert response.status_code == 400


# work on >=256
@pytest.mark.usefixtures('wipe_account')
def test_create_container_long_meta_key(container):
    cont_name = 'meta_l'
    container.create_container(cont_name=cont_name)
    long_value = 'a'*239
    meta_headers = {
        f'x-container-meta-{long_value}': 'metatest_l',
    }
    response = container.create_container_metadata(
        headers=meta_headers, cont_name=cont_name
    )
    assert response.status_code == 400


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.xfail(reason='unknown value limit')
def test_create_container_long_meta_value(container):
    cont_name = 'meta_lv'
    container.create_container(cont_name=cont_name)
    long_value = 'a'*1000
    meta_headers = {
        'x-container-meta-test': f'{long_value}',
    }
    response = container.create_container_metadata(
        headers=meta_headers, cont_name=cont_name
    )
    assert response.status_code == 400


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['format=json'])
def test_check_empty_container_stats(container, set_query_params):
    get_resp = container.get_acc_containers(query=set_query_params)
    assert not get_resp.json()
    head_resp = container.head_acc_containers()
    resp_headers = dict(head_resp.headers)
    assert resp_headers['X-Account-Bytes-Used'] == '0'
    assert resp_headers['X-Account-Container-Count'] == '0'
    assert resp_headers['X-Account-Object-Count'] == '0'
    assert resp_headers['x-account-storage-policy-cold-bytes-used'] == '0'
    assert resp_headers['x-account-storage-policy-cold-container-count'] == '0'
    assert resp_headers['x-account-storage-policy-cold-object-count'] == '0'
    assert resp_headers['X-Account-Storage-Policy-Policy-0-Bytes-Used'] == '0'
    assert resp_headers['X-Account-Storage-Policy-Policy-0-Container-Count'] == '0'
    assert resp_headers['X-Account-Storage-Policy-Policy-0-Object-Count'] == '0'


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params',
                         ['format=json&marker=1&end_marker=4'],
                         indirect=True)
def test_listing_with_markers(container, set_query_params, cont_object):
    cont_name = 'listing_m'
    container.create_container(cont_name=cont_name)
    for obj_name in [f'{cont_name}/{obj}' for obj in range(5)]:
        response = cont_object.create_object(obj_name=obj_name)
        assert response.status_code == 201
    response = container.get_container(
        query=set_query_params, cont_name=cont_name
    )
    listing = response.json()
    assert response.status_code == 200
    for obj in listing:
        assert obj['name'] in [f'{obj}' for obj in range(1, 4)]


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params',
                         ['format=json&marker=0&end_marker=5&prefix=1'],
                         indirect=True)
def test_listing_with_markers_and_prefix(container, set_query_params, cont_object):
    cont_name = 'listing_mp'
    container.create_container(cont_name=cont_name)
    for obj_name in [f'{cont_name}/{obj*5}' for obj in range(5)]:
        response = cont_object.create_object(obj_name=obj_name)
        assert response.status_code == 201
    get_resp = container.get_container(
        query=set_query_params, cont_name=cont_name
    )
    listing = get_resp.json()
    assert get_resp.status_code == 200
    for obj in listing:
        assert obj['name'] in ['10', '15']


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['format=json'])
def test_check_container_stats_after_obj_creation(container, set_query_params, cont_object):
    cont_name = 'stats_creation'
    container.create_container(cont_name=cont_name)
    listing = [f'{cont_name}/{name}' for name in range(5)]
    for obj_name in listing:
        response = cont_object.create_object(obj_name=obj_name)
        assert response.status_code == 201
    time.sleep(10)
    get_resp = container.get_container(
        query=set_query_params, cont_name=cont_name
    )
    resp_listing = get_resp.json()
    assert len(resp_listing) == len(listing)
    head_resp = container.head_container(cont_name=cont_name)
    resp_headers = dict(head_resp.headers)
    assert resp_headers['X-Container-Object-Count'] == str(len(listing))


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['format=json'])
def test_check_container_stats_after_obj_deletion(container, set_query_params, cont_object):
    cont_name = 'stats_deletion'
    container.create_container(cont_name=cont_name)
    listing = [f'{cont_name}/{name}' for name in range(5)]
    for obj_name in listing:
        response = cont_object.create_object(obj_name=obj_name)
        assert response.status_code == 201
    for obj_name in listing:
        response = cont_object.delete_object(obj_name=obj_name)
        assert response.status_code == 204
    time.sleep(10)
    get_resp = container.get_container(
        query=set_query_params, cont_name=cont_name
    )
    resp_listing = get_resp.json()
    assert not resp_listing
    head_resp = container.head_container(cont_name=cont_name)
    resp_headers = dict(head_resp.headers)
    assert resp_headers['X-Container-Object-Count'] == '0'


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['format=json'])
def test_check_account_stats_after_obj_creation(container, set_query_params, cont_object):
    cont_name = 'acc_stats_creation'
    container.create_container(cont_name=cont_name)
    listing = [f'{cont_name}/{name}' for name in range(5)]
    for obj_name in listing:
        response = cont_object.create_object(obj_name=obj_name)
        assert response.status_code == 201
    time.sleep(10)
    head_resp = container.head_acc_containers()
    resp_headers = dict(head_resp.headers)
    assert resp_headers['X-Account-Storage-Policy-Policy-0-Object-Count'] \
           == str(len(listing))


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['format=json'])
def test_check_account_stats_after_obj_deletion(container, set_query_params, cont_object):
    cont_name = 'acc_stats_deletion'
    container.create_container(cont_name=cont_name)
    listing = [f'{cont_name}/{name}' for name in range(5)]
    for obj_name in listing:
        response = cont_object.create_object(obj_name=obj_name)
        assert response.status_code == 201
    for obj_name in listing:
        response = cont_object.delete_object(obj_name=obj_name)
        assert response.status_code == 204
    time.sleep(10)
    head_resp = container.head_acc_containers()
    resp_headers = dict(head_resp.headers)
    assert resp_headers['X-Account-Storage-Policy-Policy-0-Object-Count'] \
           == '0'


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['format=json&delimiter=/'])
def test_listing_delimiter(container, set_query_params, cont_object):
    cont_name = 'delimiter'
    directory = 'dir/'
    listing = [f'{cont_name}/{directory}{name}' for name in range(5)]
    container.create_container(cont_name=cont_name)
    cont_object.create_object(obj_name=directory)
    for obj_name in listing:
        response = cont_object.create_object(obj_name=obj_name)
        assert response.status_code == 201
    get_resp = container.get_container(
        query=set_query_params, cont_name=cont_name
    )
    resp_listing = get_resp.json()
    assert len(resp_listing) == 1


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['format=json&delimiter=/&prefix=aaa'])
def test_listing_delimiter_prefix(container, set_query_params, cont_object):
    cont_name = 'delimiter_prefix'
    container.create_container(cont_name=cont_name)
    directories = ['aaa/', 'bbb/']
    for directory in directories:
        cont_object.create_object(obj_name=directory)
        listing = [f'{cont_name}/{directory}{name}' for name in range(5)]
        for obj_name in listing:
            response = cont_object.create_object(obj_name=obj_name)
            assert response.status_code == 201
    get_resp = container.get_container(
        query=set_query_params, cont_name=cont_name
    )
    resp_listing = get_resp.json()
    assert len(resp_listing) == 1


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['format=json'])
def test_pagination(container, set_query_params, cont_object):
    cont_name = 'pagination'
    container.create_container(cont_name=cont_name)
    listing = [f'{cont_name}/{name:05}' for name in range(11011)]
    for obj_name in listing:
        response = cont_object.create_object(obj_name=obj_name)
        assert response.status_code == 201
    get_resp = container.get_container_listing(
        query=set_query_params, cont_name=cont_name
    )
    resp_listing = get_resp[1]
    assert len(resp_listing) == 11011
    for obj in resp_listing:
        assert obj['name'] in [f'{name:05}' for name in range(11011)]


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['format=json&prefix=1'])
def test_pagination_prefix(container, set_query_params, cont_object):
    cont_name = 'pagination_prefix'
    container.create_container(cont_name=cont_name)
    listing = [f'{cont_name}/{name:05}' for name in range(11011)]
    for obj_name in listing:
        response = cont_object.create_object(obj_name=obj_name)
        assert response.status_code == 201
    get_resp = container.get_container(
        query=set_query_params, cont_name=cont_name
    )
    resp_listing = get_resp.json()
    assert len(resp_listing) == 1011
    for obj in resp_listing:
        assert obj['name'] in [f'{name:05}' for name in range(10000, 11011)]


@pytest.mark.usefixtures('wipe_account')
@pytest.mark.parametrize('set_query_params', ['format=json&prefix=aaa/&delimiter=/'])
def test_pagination_prefix_delimiter(container, set_query_params, cont_object):
    cont_name = 'pagination_delimiter'
    directory = 'aaa/'
    container.create_container(cont_name=cont_name)
    listing = [f'{cont_name}/{directory}{name:05}' for name in range(11001)]
    for obj_name in listing:
        response = cont_object.create_object(obj_name=obj_name)
        assert response.status_code == 201
    get_resp = container.get_container(
        query=set_query_params, cont_name=cont_name
    )
    resp_listing = get_resp.json()
    assert len(resp_listing) == 10000
