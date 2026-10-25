import re

from pirogue_admin_api import (
    PIROGUE_ADMIN_AUTH_HEADER,
    PIROGUE_ADMIN_AUTH_SCHEME)

AUTH_TOKEN_EXPRESSION = re.escape(PIROGUE_ADMIN_AUTH_SCHEME) + r" ([^\s,]+)"

def extract_auth_token(invocation_metadata):
    metadata = dict(invocation_metadata)

    if PIROGUE_ADMIN_AUTH_HEADER not in metadata:
        raise Exception("Authorization header not found")

    authorization = str(metadata.get(PIROGUE_ADMIN_AUTH_HEADER))
    auth_match = re.search(AUTH_TOKEN_EXPRESSION, authorization)

    if not auth_match:
        raise Exception("Authorization header wrong format")

    auth_token = auth_match.group(1)

    return auth_token