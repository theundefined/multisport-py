import base64
import hashlib
import logging
import os
import re
from typing import Any, Dict, List, Optional, cast
from urllib.parse import parse_qs, urlparse

import httpx

from .exceptions import AuthenticationError, MultisportError

logger = logging.getLogger(__name__)


class MultisportClient:
    """
    A client for interacting with the MultiSport API.

    Handles authentication and provides methods to fetch user information,
    card limits, card history, and related cards.
    """

    AUTH_BASE_URL = "https://login.emultisport.pl/realms/sso/"
    API_BASE_URL = "https://bam.benefitsystems.online/"
    CLIENT_ID = "ms-frontend"  # Observed in curl requests
    REDIRECT_URI = "https://app.kartamultisport.pl/"  # Observed in curl requests

    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.http_client = httpx.AsyncClient()
        self.code_verifier: str = self._generate_code_verifier()
        self.code_challenge: str = self._generate_code_challenge(self.code_verifier)

    def _generate_code_verifier(self, length=96):
        return base64.urlsafe_b64encode(os.urandom(length)).rstrip(b"=").decode("ascii")

    def _generate_code_challenge(self, code_verifier: str):
        sha256 = hashlib.sha256(code_verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(sha256).rstrip(b"=").decode("ascii")

    async def _authenticate_step1(self) -> str:
        """
        Perform the initial login flow to obtain an authorization code.

        This involves:
        1. Making a GET request to the OpenID Connect /auth endpoint to get dynamic
           parameters.
        2. Parsing the response URL to extract session_code, execution, etc.
        3. Performing a POST request with username/password and dynamic parameters.
        4. Extracting the authorization code from the redirect location.
        """
        logger.info("Step 1: Initiating authorization request to get dynamic login parameters.")
        login_init_url = (
            f"{self.AUTH_BASE_URL}protocol/openid-connect/auth?"
            f"client_id={self.CLIENT_ID}&"
            f"redirect_uri={self.REDIRECT_URI}&"
            "response_mode=fragment&response_type=code&scope=openid&"
            f"nonce={self._generate_code_verifier(16)}&"
            f"code_challenge={self.code_challenge}&"
            "code_challenge_method=S256"
        )

        # Follow redirects to get to the actual login form URL
        login_page_response = await self.http_client.get(login_init_url, follow_redirects=True)
        login_page_response.raise_for_status()

        login_form_html = login_page_response.text

        # Search for the form action URL in the HTML content
        match = re.search(r'action="([^"]*login-actions/authenticate[^"]*)"', login_form_html)
        if not match:
            logger.error("Could not find login action URL in the HTML response.")
            raise AuthenticationError("Could not find login form action URL.")

        login_action_url = match.group(1).replace("&amp;", "&")
        logger.info(f"Extracted login action URL: {login_action_url}")

        final_login_url = str(login_page_response.url)
        logger.info(f"Reached final login page URL: {final_login_url}")

        data = {
            "username": self.username,
            "password": self.password,
            "credentialId": "",
        }

        logger.info("Performing login POST request with credentials...")
        login_response = await self.http_client.post(
            login_action_url,
            data=data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": final_login_url,
                "Origin": urlparse(final_login_url).scheme + "://" + urlparse(final_login_url).netloc,
            },
        )

        # A 302 status is expected on successful login, as it redirects to the next step.
        if login_response.status_code != 302:
            logger.error(
                "Login POST failed. Expected status 302, got "
                f"{login_response.status_code}. Response: {login_response.text[:200]}"
            )
            raise AuthenticationError(f"Authentication failed: Unexpected status code {login_response.status_code}.")

        redirect_location = login_response.headers.get("Location")
        if not redirect_location:
            logger.error(
                "No redirect location found after login POST. "
                f"Response status: {login_response.status_code}, "
                f"text: {login_response.text[:200]}"
            )
            raise AuthenticationError("Authentication failed: No redirect after login POST.")

        logger.info(f"Redirect location after login: {redirect_location}")

        parsed_redirect = urlparse(redirect_location)
        if parsed_redirect.fragment:
            fragment_params = parse_qs(parsed_redirect.fragment)
            auth_code = fragment_params.get("code", [""])[0]
            if auth_code:
                logger.info(f"Successfully obtained authorization code (truncated): {auth_code[:8]}...")
                return cast(str, auth_code)

        logger.error("Failed to extract authorization code from redirect fragment: " f"{redirect_location}")
        raise AuthenticationError("Authentication failed: Could not obtain authorization code.")

    async def _exchange_code_for_tokens(self, auth_code: str) -> None:
        """Exchanges the authorization code for access and refresh tokens."""
        token_url = f"{self.AUTH_BASE_URL}protocol/openid-connect/token"

        data = {
            "grant_type": "authorization_code",
            "client_id": self.CLIENT_ID,
            "redirect_uri": self.REDIRECT_URI,
            "code": auth_code,
            "code_verifier": self.code_verifier,  # Use the generated code_verifier
        }

        logger.info("Exchanging authorization code for tokens...")
        token_response = await self.http_client.post(
            token_url,
            data=data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": self.REDIRECT_URI,
                "Origin": urlparse(self.REDIRECT_URI).scheme + "://" + urlparse(self.REDIRECT_URI).netloc,
            },
        )
        token_response.raise_for_status()
        tokens = token_response.json()

        self.access_token = tokens.get("access_token")
        self.refresh_token = tokens.get("refresh_token")

        if not self.access_token:
            logger.error(f"Access token not found in response: {tokens}")
            raise AuthenticationError("Authentication failed: Access token missing.")

        logger.info("Successfully obtained access and refresh tokens.")

    async def login(self):
        """Perform the full login process."""
        logger.info("Starting MultiSport login process...")
        try:
            auth_code = await self._authenticate_step1()
            await self._exchange_code_for_tokens(auth_code)
            logger.info("MultiSport login successful.")
        except httpx.RequestError as exc:
            raise MultisportError(f"An error occurred while requesting MultiSport API: {exc}") from exc
        except AuthenticationError:
            logger.exception("MultiSport login failed:")
            raise

    async def get_user_info(self) -> Dict[str, Any]:
        """Fetch user information from the Keycloak userinfo endpoint."""
        if not self.access_token:
            raise ValueError("Not logged in. Call client.login() first.")

        headers = {"Authorization": f"Bearer {self.access_token}"}
        response = await self.http_client.get(f"{self.AUTH_BASE_URL}protocol/openid-connect/userinfo", headers=headers)
        response.raise_for_status()
        return cast(Dict[str, Any], response.json())

    async def get_authorized_users(self) -> Dict[str, Any]:
        """Fetch authorized users from the BAM API; this should contain product IDs."""
        if not self.access_token:
            raise ValueError("Not logged in. Call client.login() first.")

        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept-Language": "pl",
        }  # Added Accept-Language from curl
        response = await self.http_client.get(f"{self.API_BASE_URL}bam/core/v1/authorized/users", headers=headers)
        response.raise_for_status()
        return cast(Dict[str, Any], response.json())

    async def get_card_limits(self, product_id: str) -> Dict[str, Any]:
        """Fetch card limits for a given product ID."""
        if not self.access_token:
            raise ValueError("Not logged in. Call client.login() first.")

        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept-Language": "pl",
        }
        response = await self.http_client.get(
            f"{self.API_BASE_URL}bam/core/v1/authorized/products/{product_id}/limits",
            headers=headers,
        )
        response.raise_for_status()
        return cast(Dict[str, Any], response.json())

    async def get_card_history(
        self,
        product_id: str,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Fetch card entry history for a given product ID.

        Optionally filters by date (YYYY-MM-DD).
        """
        if not self.access_token:
            raise ValueError("Not logged in. Call client.login() first.")

        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept-Language": "pl",
        }

        params = {}
        if date_from:
            params["dateFrom"] = date_from
        if date_to:
            params["dateTo"] = date_to

        response = await self.http_client.get(
            f"{self.API_BASE_URL}bam/core/v1/authorized/products/{product_id}/history",
            headers=headers,
            params=params,
        )
        response.raise_for_status()
        return cast(List[Dict[str, Any]], response.json())

    async def get_relations(self) -> Dict[str, Any]:
        """Fetch related cards and users."""
        if not self.access_token:
            raise ValueError("Not logged in. Call client.login() first.")

        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept-Language": "pl",
        }
        response = await self.http_client.get(
            f"{self.API_BASE_URL}bam/relations/v1/authorized/relations", headers=headers
        )
        response.raise_for_status()
        return cast(Dict[str, Any], response.json())

    async def close(self):
        """Close the HTTP client session."""
        await self.http_client.aclose()
