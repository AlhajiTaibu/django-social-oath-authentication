from typing import Dict, Any

from google.oauth2 import service_account
from googleapiclient.discovery import build

import requests
from django.conf import settings
from django.core.exceptions import ValidationError

# SERVICE_ACCOUNT_FILE = 'service-account.json'
# credentials = service_account.Credentials.from_service_account_file(
#     filename=SERVICE_ACCOUNT_FILE,
#     scopes=['https://mail.google.com'],
#     subject='abdurami.taibu@4-sure.net'
# )
#
# service = build('gmail', 'v1', credentials=credentials)
# response = service.users().messages().send(userId='me',
#                                                   body='hello peeps').execute()


GOOGLE_ID_TOKEN_INFO_URL = 'https://www.googleapis.com/oauth2/v3/tokeninfo'
GOOGLE_ACCESS_TOKEN_OBTAIN_URL = 'https://oauth2.googleapis.com/token'
GOOGLE_USER_INFO_URL = 'https://www.googleapis.com/oauth2/v3/userinfo'


def google_validate_id_token(*, id_token: str) -> bool:
    response = requests.get(
        GOOGLE_ID_TOKEN_INFO_URL,
        params={'id_token': id_token}
    )

    if not response.ok:
        raise ValidationError('id_token is invalid.')

    audience = response.json()['aud']

    if audience != settings.GOOGLE_OAUTH2_CLIENT_ID:
        raise ValidationError('Invalid audience.')

    return True


def google_get_user_id(*, id_token: str) -> str:
    response = requests.get(
        GOOGLE_ID_TOKEN_INFO_URL,
        params={'id_token': id_token}
    )

    if not response.ok:
        raise ValidationError('id_token is invalid.')

    return response.json()['sub']


def google_get_access_token(*, code: str, redirect_uri: str) -> str:
    code: str = code.replace('%2F', '/')
    data = {
        "code": code,
        "client_id": settings.GOOGLE_OAUTH2_CLIENT_ID,
        "client_secret": settings.GOOGLE_OAUTH2_CLIENT_SECRET,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code"
    }

    response = requests.post(GOOGLE_ACCESS_TOKEN_OBTAIN_URL, data=data)

    if not response.ok:
        raise ValidationError('Failed to obtain access token from Google.')

    print(f"data: {response.json()}")
    access_token = response.json()

    return access_token


def google_get_user_info(*, access_token: str) -> Dict[str, Any]:
    response = requests.get(
        GOOGLE_USER_INFO_URL,
        params={'access_token': access_token}
    )

    if not response.ok:
        raise ValidationError('Failed to obtain user info from Google.')

    return response.json()
