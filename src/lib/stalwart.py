import requests
import base64
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_auth_code(api_url, username, password):
    bearer = base64.b64encode(f"{username}:{password}".encode()).decode("utf-8")
    res = requests.post(f"{api_url}/api/oauth", headers={"Authorization": f"Basic {bearer}"}, verify=False, json={
        'type': "Code",
        'client_id': "webadmin",
        'redirect_uri': None
    })

    if res.status_code != 200:
        return False

    json = res.json()
    return json["data"]["code"]


def get_access_token(api_url, code):
    res = requests.post(f"{api_url}/auth/token", verify=False, data={
        "grant_type": "authorization_code",
        "client_id": "webadmin",
        "code": code,
        "redirect_uri": ""
    })

    if res.status_code != 200:
        return False

    json = res.json()
    return json["access_token"]


def get_acme_cert(api_url, access_token, directory_id):
    res = requests.get(f"{api_url}/api/settings/list?prefix=acme.{directory_id}", headers={"Authorization": f"Bearer {access_token}"}, verify=False)
    if res.status_code != 200:
        return False

    json = res.json()
    return json["data"]["items"]["cert"]
