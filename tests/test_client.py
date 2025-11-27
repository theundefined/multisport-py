import re

import pytest
from pytest_httpx import HTTPXMock

from multisport_py.client import MultisportClient
from multisport_py.exceptions import AuthenticationError

# Dummy login form HTML containing the action URL
LOGIN_FORM_HTML = """
<html><body>
<form id="kc-form-login" action="https://login.emultisport.pl/realms/sso/login-actions/authenticate?session_code=mock_session_code&amp;execution=mock_execution&amp;client_id=ms-frontend&amp;tab_id=mock_tab_id">
</form>
</body></html>
"""

# Dummy token response
TOKEN_RESPONSE_JSON = {
    "access_token": "mock_access_token",
    "refresh_token": "mock_refresh_token",
    "token_type": "Bearer",
    "expires_in": 300,
}


@pytest.mark.asyncio
async def test_login_success(httpx_mock: HTTPXMock):
    """Test the full successful login flow by mocking API responses."""
    # 1. Mock the initial GET request to the /auth endpoint
    httpx_mock.add_response(
        method="GET",
        url=re.compile(r"https://login.emultisport.pl/realms/sso/protocol/openid-connect/auth\?.*"),
        text=LOGIN_FORM_HTML,
        status_code=200,
    )

    # 2. Mock the POST request to the login action URL
    httpx_mock.add_response(
        method="POST",
        url=re.compile(r"https://login.emultisport.pl/realms/sso/login-actions/authenticate\?.*"),
        status_code=302,
        headers={"Location": "https://app.kartamultisport.pl/#code=mock_auth_code"},
    )
    # 3. Mock the POST request to the /token endpoint
    httpx_mock.add_response(
        method="POST",
        url="https://login.emultisport.pl/realms/sso/protocol/openid-connect/token",
        json=TOKEN_RESPONSE_JSON,
        status_code=200,
    )

    # --- Run the test ---
    client = MultisportClient(username="testuser", password="testpassword")
    await client.login()

    # --- Assertions ---
    assert client.access_token == "mock_access_token"
    assert client.refresh_token == "mock_refresh_token"

    await client.close()


@pytest.mark.asyncio
async def test_login_fails_on_bad_credentials(httpx_mock: HTTPXMock):
    """Test that login fails when the authentication server returns an error."""
    # 1. Mock the initial GET request
    httpx_mock.add_response(
        method="GET",
        url=re.compile(r"https://login.emultisport.pl/realms/sso/protocol/openid-connect/auth\?.*"),
        text=LOGIN_FORM_HTML,
        status_code=200,
    )

    # 2. Mock the POST request to fail (e.g., return 401 or a non-redirect status)
    httpx_mock.add_response(
        method="POST",
        url=re.compile(r"https://login.emultisport.pl/realms/sso/login-actions/authenticate\?.*"),
        status_code=401,
        text="Invalid credentials",
    )

    client = MultisportClient(username="wronguser", password="wrongpassword")
    with pytest.raises(AuthenticationError, match="Authentication failed: Unexpected status code 401"):
        await client.login()

    await client.close()


@pytest.fixture
def authenticated_client() -> MultisportClient:
    """Provide a client that is already 'logged in' by setting the access token."""
    client = MultisportClient(username="test", password="test")
    client.access_token = "fake_access_token"
    return client


USER_INFO_RESPONSE = {
    "sub": "d8417d59-393d-7893-acfb-acee0aaec83b",
    "ms_products": [308896283999],
    "name": "Test User",
}

AUTH_USERS_RESPONSE = {
    "products": [
        {
            "id": "308896283999",
            "status": "active",
            "holder": {"firstName": "Test", "lastName": "User"},
        }
    ]
}


@pytest.mark.asyncio
async def test_get_user_info(httpx_mock: HTTPXMock, authenticated_client: MultisportClient):
    """Tests fetching user info from a logged-in client."""
    httpx_mock.add_response(
        method="GET",
        url="https://login.emultisport.pl/realms/sso/protocol/openid-connect/userinfo",
        json=USER_INFO_RESPONSE,
        status_code=200,
    )

    user_info = await authenticated_client.get_user_info()

    assert user_info == USER_INFO_RESPONSE
    await authenticated_client.close()


@pytest.mark.asyncio
async def test_get_authorized_users(httpx_mock: HTTPXMock, authenticated_client: MultisportClient):
    """Tests fetching authorized users from a logged-in client."""
    httpx_mock.add_response(
        method="GET",
        url="https://bam.benefitsystems.online/bam/core/v1/authorized/users",
        json=AUTH_USERS_RESPONSE,
        status_code=200,
    )

    auth_users = await authenticated_client.get_authorized_users()

    assert auth_users == AUTH_USERS_RESPONSE
    await authenticated_client.close()


LIMITS_RESPONSE = {"remainingVisits": 4}
HISTORY_RESPONSE = [{"dateFrom": "01-11-2025", "count": 1}]


@pytest.mark.asyncio
async def test_get_card_limits(httpx_mock: HTTPXMock, authenticated_client: MultisportClient):
    """Tests fetching card limits from a logged-in client."""
    product_id = "12345"
    httpx_mock.add_response(
        method="GET",
        url=f"https://bam.benefitsystems.online/bam/core/v1/authorized/products/{product_id}/limits",
        json=LIMITS_RESPONSE,
        status_code=200,
    )

    limits = await authenticated_client.get_card_limits(product_id)

    assert limits == LIMITS_RESPONSE
    await authenticated_client.close()


@pytest.mark.asyncio
async def test_get_card_history(httpx_mock: HTTPXMock, authenticated_client: MultisportClient):
    """Tests fetching card history from a logged-in client."""
    product_id = "12345"
    httpx_mock.add_response(
        method="GET",
        url=f"https://bam.benefitsystems.online/bam/core/v1/authorized/products/{product_id}/history?dateFrom=2025-01-01&dateTo=2025-01-31",
        json=HISTORY_RESPONSE,
        status_code=200,
    )

    history = await authenticated_client.get_card_history(product_id, date_from="2025-01-01", date_to="2025-01-31")

    assert history == HISTORY_RESPONSE
    await authenticated_client.close()
