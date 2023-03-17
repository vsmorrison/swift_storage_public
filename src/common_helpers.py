import requests


# полная очистка аккаунта от контейнеров, папок и объектов
def wipe_account(base_url, token):
    query = 'format=json'
    default_query = query
    containers_del_listing = []
    objects_del_listing = []
    while True:
        cont_response = requests.get(base_url, headers=token, params=query)
        query = default_query
        cont_listing = cont_response.json()
        if not cont_listing:
            break
        for cont in cont_listing:
            containers_del_listing.append(cont)
        last_container = cont_listing[-1]["name"]
        query = f"{query}&marker={last_container}"
    for cont in containers_del_listing:
        if cont['count']:
            cont_url = f"{base_url}/{cont['name']}"
            while True:
                obj_response = requests.get(cont_url, headers=token, params=query)
                query = default_query
                obj_listing = obj_response.json()
                if not obj_listing:
                    break
                for obj in obj_listing:
                    objects_del_listing.append(obj)
                last_object = obj_listing[-1]["name"]
                query = f"{query}&marker={last_object}"
            for obj in objects_del_listing:
                del_obj_url = f"{base_url}/{cont['name']}/{obj['name']}"
                requests.delete(del_obj_url, headers=token)
            objects_del_listing = []
        c_del_url = f"{base_url}/{cont['name']}"
        requests.delete(c_del_url, headers=token)
