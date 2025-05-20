#!/usr/bin/env python3

import logging
import re
import tempfile
import os

import ghstack.github
import ghstack.github_utils
import ghstack.shell


def main(
    pull_request: str,
    github: ghstack.github.GitHubEndpoint,
    sh: ghstack.shell.Shell,
    remote_name: str,
) -> None:

    params = ghstack.github_utils.parse_pull_request(
        pull_request, sh=sh, remote_name=remote_name
    )
    head_ref = github.get_head_ref(**params)
    orig_ref = re.sub(r"/head$", "/orig", head_ref)
    if orig_ref == head_ref:
        logging.warning(
            "The ref {} doesn't look like a ghstack reference".format(head_ref)
        )

    # Try to fetch normally first
    try:
        sh.git("fetch", "--prune", remote_name)
    except RuntimeError as e:
        # If fetch fails and we have an OAuth token, try using it
        if hasattr(github, 'oauth_token') and github.oauth_token:
            logging.info("Attempting to fetch using OAuth token authentication...")
            
            # Get the remote URL
            remote_url = sh.git("remote", "get-url", remote_name)
            
            if remote_url.startswith("https://"):
                # Create a temporary remote with auth token
                temp_remote_name = "ghstack-temp-fetch"
                
                # Extract owner and repo name from remote_url
                # This handles both github.com/owner/repo and github_url/owner/repo patterns
                owner_repo_match = re.search(r"https://[^/]+/([^/]+)/([^/]+)(?:\.git)?$", remote_url)
                if owner_repo_match:
                    owner = owner_repo_match.group(1)
                    repo = owner_repo_match.group(2)
                    
                    # Create auth URL
                    github_url = params.get("github_url", "github.com")
                    auth_url = f"https://x-access-token:{github.oauth_token}@{github_url}/{owner}/{repo}.git"
                    
                    try:
                        # Add temporary remote with auth token
                        sh.git("remote", "add", temp_remote_name, auth_url)
                        sh.git("fetch", "--prune", temp_remote_name)
                        
                        # Update remote_name to our temp remote for checkout
                        remote_name = temp_remote_name
                    except Exception:
                        # Fall back to original error
                        raise e
                    finally:
                        # We'll remove the temp remote after checkout
                        pass
                else:
                    # Couldn't parse owner/repo, fall back to original error
                    raise e
        else:
            # No OAuth token, so just re-raise the original error
            raise e

    try:
        # Checkout the branch
        sh.git("checkout", remote_name + "/" + orig_ref)
    finally:
        # Clean up temp remote if we created one
        if 'temp_remote_name' in locals():
            try:
                sh.git("remote", "remove", temp_remote_name)
            except Exception:
                pass
