#!/usr/bin/env python3

import json
import logging
import re
import time
from typing import Any, Dict, Optional, Sequence, Tuple, Union

import requests

import ghstack.github

MAX_RETRIES = 5
INITIAL_BACKOFF_SECONDS = 60


class RealGitHubEndpoint(ghstack.github.GitHubEndpoint):
    """
    A class representing a GitHub endpoint we can send queries to.
    It supports both GraphQL and REST interfaces.
    """

    # The URL of the GraphQL endpoint to connect to
    @property
    def graphql_endpoint(self) -> str:
        if self.github_url == "github.com":
            return f"https://api.{self.github_url}/graphql"
        else:
            return f"https://{self.github_url}/api/graphql"

    # The base URL of the REST endpoint to connect to (all REST requests
    # will be subpaths of this URL)
    @property
    def rest_endpoint(self) -> str:
        if self.github_url == "github.com":
            return f"https://api.{self.github_url}"
        else:
            return f"https://{self.github_url}/api/v3"

    # The base URL of regular WWW website, in case we need to manually
    # interact with the real website
    www_endpoint: str = "https://{github_url}"

    # The string OAuth token to authenticate to the GraphQL server with.
    # May be None if we're doing public access only.
    oauth_token: Optional[str]

    # The URL of a proxy to use for these connections (for
    # Facebook users, this is typically 'http://fwdproxy:8080')
    proxy: Optional[str]

    # The certificate bundle to be used to verify the connection.
    # Passed to requests as 'verify'.
    verify: Optional[str]

    # Client side certificate to use when connecitng.
    # Passed to requests as 'cert'.
    cert: Optional[Union[str, Tuple[str, str]]]

    def __init__(
        self,
        oauth_token: Optional[str],
        github_url: str,
        proxy: Optional[str] = None,
        verify: Optional[str] = None,
        cert: Optional[Union[str, Tuple[str, str]]] = None,
    ):
        self.oauth_token = oauth_token
        self.proxy = proxy
        self.github_url = github_url
        self.verify = verify
        self.cert = cert

    def push_hook(self, refName: Sequence[str]) -> None:
        pass

    def graphql(self, query: str, **kwargs: Any) -> Any:
        headers = {}
        if self.oauth_token:
            headers["Authorization"] = "bearer {}".format(self.oauth_token)

        endpoint = self.graphql_endpoint.format(github_url=self.github_url)
        logging.debug(f"# POST {endpoint}")
        logging.debug("Request GraphQL query:\n{}".format(query))
        logging.debug(
            "Request GraphQL variables:\n{}".format(json.dumps(kwargs, indent=1))
        )

        try:
            resp = requests.post(
                endpoint,
                json={"query": query, "variables": kwargs},
                headers=headers,
                proxies=self._proxies(),
                verify=self.verify,
                cert=self.cert,
            )

            logging.debug(f"Response status: {resp.status_code}")
            
            # Log response content for debugging
            if resp.status_code != 200:
                logging.error(f"Error response from GitHub API: {resp.status_code}")
                logging.error(f"Response headers: {resp.headers}")
                logging.error(f"Response text: {resp.text[:1000]}")  # Limit to first 1000 chars
                
                if resp.status_code == 401:
                    raise RuntimeError(
                        "GitHub API returned 401 Unauthorized. Your OAuth token may be invalid or expired. "
                        "For private repositories, make sure your token has the 'repo' scope."
                    )
                elif resp.status_code == 403:
                    raise RuntimeError(
                        "GitHub API returned 403 Forbidden. You might not have permission to access this repository, "
                        "or your OAuth token might not have sufficient permissions."
                    )
                elif resp.status_code == 404:
                    raise RuntimeError(
                        "GitHub API returned 404 Not Found. The repository might not exist, "
                        "or you might not have access to it."
                    )
                
                # Always raise for status to trigger general error handling
                resp.raise_for_status()

            try:
                r = resp.json()
            except ValueError as e:
                logging.error(f"Failed to parse JSON response: {str(e)}")
                logging.error(f"Response text: {resp.text[:1000]}")  # Limit to first 1000 chars
                
                # Check if response might be HTML (often an error page)
                if resp.text.strip().startswith(("<!DOCTYPE", "<html")):
                    logging.error("Response appears to be HTML instead of JSON - likely an error page")
                    
                    # Extract title if possible for more context
                    title_match = re.search(r"<title>(.*?)</title>", resp.text, re.DOTALL)
                    if title_match:
                        error_title = title_match.group(1).strip()
                        logging.error(f"Error page title: {error_title}")
                
                raise RuntimeError(
                    "GitHub API returned a non-JSON response. This could indicate:\n"
                    "1. Network connectivity issues\n"
                    "2. Authentication problems with your OAuth token\n"
                    "3. GitHub API endpoint might be incorrect or unavailable\n\n"
                    f"Status code: {resp.status_code}"
                ) from e
            
            pretty_json = json.dumps(r, indent=1)
            logging.debug("Response JSON:\n{}".format(pretty_json))

            if "errors" in r:
                logging.error(f"GraphQL errors: {json.dumps(r['errors'], indent=2)}")
                
                # Check for common authorization errors
                for error in r.get("errors", []):
                    if "type" in error and error["type"] == "FORBIDDEN":
                        raise RuntimeError(
                            "GitHub GraphQL API returned a FORBIDDEN error. "
                            "For private repositories, make sure your OAuth token has the 'repo' scope."
                        )
                
                raise RuntimeError(pretty_json)

            return r
        except requests.exceptions.RequestException as e:
            logging.error(f"Request exception: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                logging.error(f"Response status: {e.response.status_code}")
                logging.error(f"Response text: {e.response.text[:1000]}")
            
            raise RuntimeError(
                f"Failed to connect to GitHub API: {str(e)}\n"
                "Please check your network connection and GitHub API endpoint configuration."
            ) from e

    def _proxies(self) -> Dict[str, str]:
        if self.proxy:
            return {"http": self.proxy, "https": self.proxy}
        else:
            return {}

    def get_head_ref(self, **params: Any) -> str:

        if self.oauth_token:
            return super().get_head_ref(**params)
        else:
            owner = params["owner"]
            name = params["name"]
            number = params["number"]
            resp = requests.get(
                f"{self.www_endpoint.format(github_url=self.github_url)}/{owner}/{name}/pull/{number}",
                proxies=self._proxies(),
                verify=self.verify,
                cert=self.cert,
            )
            logging.debug("Response status: {}".format(resp.status_code))

            r = resp.text
            if m := re.search(r'<clipboard-copy.+?value="(gh/[^/]+/\d+/head)"', r):
                return m.group(1)
            else:
                # couldn't find, fall back to regular query
                return super().get_head_ref(**params)

    def rest(self, method: str, path: str, **kwargs: Any) -> Any:
        assert self.oauth_token
        headers = {
            "Authorization": "token " + self.oauth_token,
            "Content-Type": "application/json",
            "User-Agent": "ghstack",
            "Accept": "application/vnd.github.v3+json",
        }

        url = self.rest_endpoint.format(github_url=self.github_url) + "/" + path
        logging.debug(f"# {method.upper()} {url}")
        logging.debug("Request body:\n{}".format(json.dumps(kwargs, indent=1)))

        backoff_seconds = INITIAL_BACKOFF_SECONDS
        for attempt in range(0, MAX_RETRIES):
            try:
                resp: requests.Response = getattr(requests, method)(
                    url,
                    json=kwargs,
                    headers=headers,
                    proxies=self._proxies(),
                    verify=self.verify,
                    cert=self.cert,
                )

                logging.debug(f"Response status: {resp.status_code}")

                # Log response content for debugging non-200 responses
                if resp.status_code != 200:
                    logging.error(f"Error response from GitHub API: {resp.status_code}")
                    logging.error(f"Response headers: {resp.headers}")
                    logging.error(f"Response text: {resp.text[:1000]}")  # Limit to first 1000 chars

                # Per Github rate limiting: https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api?apiVersion=2022-11-28#exceeding-the-rate-limit
                if resp.status_code in (403, 429):
                    remaining_count = resp.headers.get("x-ratelimit-remaining")
                    reset_time = resp.headers.get("x-ratelimit-reset")

                    if remaining_count == "0" and reset_time:
                        sleep_time = int(reset_time) - int(time.time())
                        logging.warning(
                            f"Rate limit exceeded. Sleeping until reset in {sleep_time} seconds."
                        )
                        time.sleep(sleep_time)
                        continue
                    else:
                        retry_after_seconds = resp.headers.get("retry-after")
                        if retry_after_seconds:
                            sleep_time = int(retry_after_seconds)
                            logging.warning(
                                f"Secondary rate limit hit. Sleeping for {sleep_time} seconds."
                            )
                        else:
                            sleep_time = backoff_seconds
                            logging.warning(
                                f"Secondary rate limit hit. Sleeping for {sleep_time} seconds (exponential backoff)."
                            )
                            backoff_seconds *= 2
                        time.sleep(sleep_time)
                        continue

                if resp.status_code == 401:
                    raise RuntimeError(
                        "GitHub API returned 401 Unauthorized. Your OAuth token may be invalid or expired. "
                        "For private repositories, make sure your token has the 'repo' scope."
                    )

                if resp.status_code == 404:
                    raise ghstack.github.NotFoundError(
                        """\
GitHub raised a 404 error on the request for
{url}.
Usually, this doesn't actually mean the page doesn't exist; instead, it
usually means that you didn't configure your OAuth token with enough
permissions.  Please create a new OAuth token at
https://{github_url}/settings/tokens and DOUBLE CHECK that you checked
"public_repo" for permissions, or "repo" for private repository access.
Update ~/.ghstackrc with your new token value.

For private repositories, make sure your token has the full "repo" scope,
not just "public_repo".
""".format(
                            url=url, github_url=self.github_url
                        )
                    )

                try:
                    r = resp.json()
                except ValueError as e:
                    logging.error(f"Failed to parse JSON response: {str(e)}")
                    logging.error(f"Response text: {resp.text[:1000]}")  # Limit to first 1000 chars
                    
                    # Check if response might be HTML (often an error page)
                    if resp.text.strip().startswith(("<!DOCTYPE", "<html")):
                        logging.error("Response appears to be HTML instead of JSON - likely an error page")
                        
                        # Extract title if possible for more context
                        title_match = re.search(r"<title>(.*?)</title>", resp.text, re.DOTALL)
                        if title_match:
                            error_title = title_match.group(1).strip()
                            logging.error(f"Error page title: {error_title}")
                    
                    raise RuntimeError(
                        "GitHub API returned a non-JSON response. This could indicate:\n"
                        "1. Network connectivity issues\n"
                        "2. Authentication problems with your OAuth token\n"
                        "3. GitHub API endpoint might be incorrect or unavailable\n\n"
                        f"Status code: {resp.status_code}"
                    ) from e
                
                pretty_json = json.dumps(r, indent=1)
                logging.debug("Response JSON:\n{}".format(pretty_json))

                resp.raise_for_status()
                return r
            
            except requests.exceptions.RequestException as e:
                logging.error(f"Request exception on attempt {attempt+1}/{MAX_RETRIES}: {str(e)}")
                if hasattr(e, 'response') and e.response is not None:
                    logging.error(f"Response status: {e.response.status_code}")
                    logging.error(f"Response text: {e.response.text[:1000]}")
                
                # If this is the last retry, raise the error
                if attempt == MAX_RETRIES - 1:
                    raise RuntimeError(
                        f"Failed to connect to GitHub API after {MAX_RETRIES} attempts: {str(e)}\n"
                        "Please check your network connection and GitHub API endpoint configuration."
                    ) from e
                
                # Otherwise, wait before retrying
                sleep_time = backoff_seconds * (attempt + 1)
                logging.warning(f"Retrying in {sleep_time} seconds...")
                time.sleep(sleep_time)

        # This line should not be reached but is here for completeness
        raise RuntimeError("Exceeded maximum retries due to GitHub rate limiting")
