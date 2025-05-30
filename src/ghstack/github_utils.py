#!/usr/bin/env python3

import re
from typing import Optional
import logging

from typing_extensions import TypedDict

import ghstack.github
import ghstack.shell
from ghstack.types import GitHubRepositoryId

GitHubRepoNameWithOwner = TypedDict(
    "GitHubRepoNameWithOwner",
    {
        "owner": str,
        "name": str,
    },
)


def get_github_repo_name_with_owner(
    *,
    sh: ghstack.shell.Shell,
    github_url: str,
    remote_name: str,
) -> GitHubRepoNameWithOwner:
    # Grovel in remotes to figure it out
    remote_url = sh.git("remote", "get-url", remote_name)
    logging.debug(f"Parsing remote URL: {remote_url}")
    
    # Handle SSH format (git@github.com:owner/repo.git)
    ssh_pattern = re.compile(r'^git@[^:]+:([^/]+)/([^.]+)(?:\.git)?$')
    m = ssh_pattern.match(remote_url)
    if m:
        owner = m.group(1)
        name = m.group(2)
        logging.debug(f"Parsed SSH URL: owner={owner}, name={name}")
        return {"owner": owner, "name": name}
    
    # Handle HTTPS format (https://github.com/owner/repo.git)
    https_pattern = re.compile(r'https://[^/]+/([^/]+)/([^.]+)(?:\.git)?$')
    m = https_pattern.match(remote_url)
    if m:
        owner = m.group(1)
        name = m.group(2)
        logging.debug(f"Parsed HTTPS URL: owner={owner}, name={name}")
        return {"owner": owner, "name": name}
    
    # Handle HTTPS with auth token (https://x-access-token:TOKEN@github.com/owner/repo.git)
    auth_pattern = re.compile(r'https://x-access-token:[^@]+@[^/]+/([^/]+)/([^.]+)(?:\.git)?$')
    m = auth_pattern.match(remote_url)
    if m:
        owner = m.group(1)
        name = m.group(2)
        logging.debug(f"Parsed HTTPS auth URL: owner={owner}, name={name}")
        return {"owner": owner, "name": name}
    
    # If we get here, none of our patterns matched
    raise RuntimeError(
        f"Couldn't determine repo owner and name from url: {remote_url}\n"
        f"Please ensure your git remote URL is in one of the following formats:\n"
        f"  SSH: git@github.com:owner/repo.git\n"
        f"  HTTPS: https://github.com/owner/repo.git"
    )


GitHubRepoInfo = TypedDict(
    "GitHubRepoInfo",
    {
        "name_with_owner": GitHubRepoNameWithOwner,
        "id": GitHubRepositoryId,
        "is_fork": bool,
        "default_branch": str,
    },
)


def get_github_repo_info(
    *,
    github: ghstack.github.GitHubEndpoint,
    sh: ghstack.shell.Shell,
    repo_owner: Optional[str] = None,
    repo_name: Optional[str] = None,
    github_url: str,
    remote_name: str,
) -> GitHubRepoInfo:
    if repo_owner is None or repo_name is None:
        name_with_owner = get_github_repo_name_with_owner(
            sh=sh,
            github_url=github_url,
            remote_name=remote_name,
        )
    else:
        name_with_owner = {"owner": repo_owner, "name": repo_name}

    # TODO: Cache this guy
    repo = github.graphql(
        """
        query ($owner: String!, $name: String!) {
            repository(name: $name, owner: $owner) {
                id
                isFork
                defaultBranchRef {
                    name
                }
            }
        }""",
        owner=name_with_owner["owner"],
        name=name_with_owner["name"],
    )["data"]["repository"]

    return {
        "name_with_owner": name_with_owner,
        "id": repo["id"],
        "is_fork": repo["isFork"],
        "default_branch": repo["defaultBranchRef"]["name"],
    }


RE_PR_URL = re.compile(
    r"^https://(?P<github_url>[^/]+)/(?P<owner>[^/]+)/(?P<name>[^/]+)/pull/(?P<number>[0-9]+)/?$"
)

GitHubPullRequestParams = TypedDict(
    "GitHubPullRequestParams",
    {
        "github_url": str,
        "owner": str,
        "name": str,
        "number": int,
    },
)


def parse_pull_request(
    pull_request: str,
    *,
    sh: Optional[ghstack.shell.Shell] = None,
    remote_name: Optional[str] = None,
) -> GitHubPullRequestParams:
    m = RE_PR_URL.match(pull_request)
    if not m:
        # We can reconstruct the URL if just a PR number is passed
        if sh is not None and remote_name is not None:
            remote_url = sh.git("remote", "get-url", remote_name)
            # Do not pass the shell to avoid infinite loop
            try:
                return parse_pull_request(remote_url + "/pull/" + pull_request)
            except RuntimeError:
                # Fall back on original error message
                pass
        raise RuntimeError("Did not understand PR argument.  PR must be URL")

    github_url = m.group("github_url")
    owner = m.group("owner")
    name = m.group("name")
    number = int(m.group("number"))
    return {"github_url": github_url, "owner": owner, "name": name, "number": number}
