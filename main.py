import os
import time
import httpx
import hmac
import logging
from re import compile
from uuid import uuid4
from jwt import encode as jwt_encode
from datetime import datetime
from hashlib import sha256
from base64 import b64encode
from boto3 import client as aws_client
from time import sleep
from botocore.exceptions import ClientError
from fastapi import FastAPI, HTTPException, Request, Header, BackgroundTasks
from fastapi.responses import FileResponse
from typing import List, Dict, Any

# Set up logging to see the secret alerts in the console
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secret-scanner")

app = FastAPI(title="GitHub Enterprise Repo Reader & Secret Scanner")

# --- Configuration ---
GITHUB_APP_ID = os.getenv("GITHUB_APP_ID")
GITHUB_API_URL = os.getenv("GITHUB_API_URL", "https://api.github.com")
GITHUB_PRIVATE_KEY_PATH = os.getenv("GITHUB_PRIVATE_KEY_PATH", "/app/certs/github.key")
FAVICON_PATH = os.getenv("FAVICON_PATH", "favicon.ico")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")
SPLUNK_URL = os.getenv("SPLUNK_URL")
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN")
SPLUNK_INDEX = os.getenv("SPLUNK_INDEX", "github")
SPLUNK_CHANNEL = os.getenv("SPLUNK_CHANNEL")
SOURCE_NAME = os.getenv("SOURCE_NAME", "Github Scanner")

# --- Regex Patterns for AWS Secrets ---
# 1. AWS Access Key ID (Standard 20-char uppercase starting with specific prefixes)
AWS_ACCESS_KEY_PATTERN = compile(r"(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}")
# 2. AWS Secret Access Key (40-char base64-like string)
AWS_SECRET_KEY_PATTERN = compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")

# --- Helper Functions ---

def get_jwt() -> str:
    """
    generate JWT for requests made to Github API
    """
    if not GITHUB_APP_ID:
        raise HTTPException(status_code=500, detail="GITHUB_APP_ID not set")
    try:
        with open(GITHUB_PRIVATE_KEY_PATH, "r") as f:
            private_key = f.read()
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail=f"Private key not found at {GITHUB_PRIVATE_KEY_PATH}")

    payload = {
        "iat": int(time.time()) - 60,
        "exp": int(time.time()) + (10 * 60),
        "iss": GITHUB_APP_ID
    }
    return jwt_encode(payload, private_key, algorithm="RS256")


async def http_request(client: httpx.AsyncClient, url: str, headers: dict, method="GET", body={}, follow_redirects=False):
    """
    Do async HTTP request. Avoid the rate limit of Github API
    """
    response = None
    if method == "GET":
        response = await client.get(url, headers=headers, follow_redirects=follow_redirects)
    
    elif method == "POST":
        response = await client.post(url, headers=headers, json=body, follow_redirects=follow_redirects)
    
    retry_after = response.headers.get("retry_after")
    # Means the rate limit has been reached
    if retry_after:
        sleep(int(retry_after) + 1)
        return await http_request(client, url, headers, method, body, follow_redirects)

    return response 


async def get_installation_token(client: httpx.AsyncClient, installation_id: int) -> str:
    """
    Get the access token for installation (org)
    """
    app_jwt = get_jwt()
    headers = {
        "Authorization": f"Bearer {app_jwt}",
        "Accept": "application/vnd.github+json"
    }
    url = f"{GITHUB_API_URL}/app/installations/{installation_id}/access_tokens"
    response = await http_request(client, url, headers=headers, method="POST")
    if response.status_code != 201:
        logger.error(f"Failed to get token for installation {installation_id}: {response.text}")
        raise Exception("Failed to get installation token")
    return response.json()["token"]      


def verify_webhook_signature(payload_body: bytes, secret_token: str, signature_header: str):
    """
    Check for valid signature and headers in the webhook call
    """
    if not signature_header:
        raise HTTPException(status_code=403, detail="x-hub-signature-256 header is missing!")
    hash_object = hmac.new(secret_token.encode("utf-8"), msg=payload_body, digestmod=sha256)
    expected_signature = "sha256=" + hash_object.hexdigest()
    if not hmac.compare_digest(expected_signature, signature_header):
        raise HTTPException(status_code=403, detail="Request signature is invalid")


def validate_secret(access_key, secret_key):
    """
    Check if the given AWS access key and secret key is valid
    """
    try:
        sts = aws_client("sts", aws_access_key_id=access_key, aws_secret_access_key=secret_key)
        sts.get_caller_identity()
        return True
    
    except ClientError:
        return False


async def get_all_pages(client: httpx.AsyncClient, url: str, headers: Dict) -> List[Any]:
    """
    Async helper to handle GitHub pagination.
    """
    results = []
    while url:
        response = await http_request(client, url, headers=headers)
        if response.status_code != 200:
            # We log error but don"t crash entire loop, just return what we have or throw
            print(f"Error fetching {url}: {response.text}")
            break
            
        data = response.json()
        
        # "repositories" key is used in some endpoints, generic list in others
        if isinstance(data, dict) and "repositories" in data:
            results.extend(data["repositories"])
        elif isinstance(data, list):
            results.extend(data)
            
        # Handle Pagination via Link header
        # httpx.Response.links returns a dictionary of parsed link headers
        if "next" in response.links:
            url = response.links["next"]["url"]
        else:
            url = None
            
    return results

async def generate_alerts(client: httpx.AsyncClient, secrets: dict, repo: str, owner: str):
    """
    Send alerts of only valid secrets to Splunk HTTP Endpoint
    """
    for access_key, ak_details in secrets["access_keys"].items():
        for secret_key, sk_details in secrets["secret_keys"].items():
            if validate_secret(access_key, secret_key):
                ak_snippet = f"{access_key[:4]}****{access_key[-4:]}"
                sk_snippet = f"{secret_key[:4]}****{secret_key[-4:]}"
                print(f"Found valid AWS secrets. AK: {ak_snippet}. SK: {sk_snippet}")

                # Add a single commit if the ak and sk are in the same file and commit Id
                if ak_details["commit"] == sk_details["commit"] and ak_details["filename"] == sk_details["filename"]:
                    commits = [ak_details]

                # Add the details of both commits if the ak and sk are in different files or commits
                else:
                    commits = [ak_details, sk_details]

                event_id = str(uuid4())
                body = {
                    "event": {
                        "eventId": event_id,
                        "accessKeyDigest": b64encode(sha256(access_key.encode()).hexdigest().encode()).decode(),
                        "accessKey": ak_snippet,
                        "secretKey": sk_snippet,
                        "organization": owner,
                        "repository": repo,
                        "commits": commits
                    },
                    "sourcetype": "_json",
                    "time": int(datetime.now().timestamp()),
                    "index": SPLUNK_INDEX,
                    "source": SOURCE_NAME
                }

                headers = {
                    "Authorization": f"Splunk {SPLUNK_TOKEN}",
                    "X-Splunk-Request-Channel": SPLUNK_CHANNEL   
                }

                response = await http_request(client, SPLUNK_URL, headers, method="POST", body=body)
                
                if response.status_code in (200, 201):
                    print(f"Successfully posted Event ID: {event_id}")
                else:
                    print(response.json())


async def scan_commit(client: httpx.AsyncClient, commit_url, headers, branch_name="main", secrets={"access_keys":{}, "secret_keys":{}}):
    # Make a call to the commit url
    response = await http_request(client, commit_url, headers)
    if response.status_code == 200:
        data = response.json()

        for file in data["files"]:
            # Analyze only added or modified files. Ignore any file as well that does not include patch (ex binary files)
            if file["status"] in ("modified", "added") and "patch" in file:
                diff_text = file["patch"]
                # Ignore files with no change
                if not diff_text:
                    continue

                added_lines = "\n".join([l for l in diff_text.split("\n") if l.startswith("+") and not l.startswith("+++")])
                
                # Detect secrets in the commit
                access_keys = AWS_ACCESS_KEY_PATTERN.findall(added_lines)
                secret_keys = AWS_SECRET_KEY_PATTERN.findall(added_lines)

                if access_keys or secret_keys:
                    # Generate payload for the alert
                    secret_details = {
                        "commit": data["sha"],
                        "filename": file["filename"],
                        "branch": branch_name
                    }
                    secret_details.update(data["commit"])

                    # Delete unnecessary fields
                    del secret_details["tree"]
                    del secret_details["url"]
                    del secret_details["verification"]
                    del secret_details["comment_count"]

                    # Add fields to provide more context
                    secret_details["verified"] = data["commit"]["verification"]["verified"]
                    secret_details["url"] = data["html_url"]

                    for access_key in access_keys:
                        logger.warning(f"🚨 AWS ACCESS KEY ID DETECTED in {file['filename']}!")
                        secrets["access_keys"][access_key] = secret_details
                    
                    for secret_key in secret_keys:
                        logger.warning(f"🚨 Possible AWS SECRET KEY DETECTED in {file['filename']}!")
                        secrets["secret_keys"][secret_key] = secret_details

    else:
        logger.info("Could not retrieve the commit content")

    return secrets


async def get_installations(client: httpx.AsyncClient):            
    # 1. Authenticate as the App to find installations
    app_jwt = get_jwt()
    app_headers = {
        "Authorization": f"Bearer {app_jwt}",
        "Accept": "application/vnd.github+json"
    }
    
    # 2. Get installations
    install_response = await http_request(client, f"{GITHUB_API_URL}/app/installations", headers=app_headers)
    
    if install_response.status_code != 200:
        raise HTTPException(status_code=install_response.status_code, detail=install_response.text)
    
    return install_response.json()


# --- Background Task for Full Scan ---

async def background_scan_all_branches(installation_id: int, owner: str, repo: str):
    """
    1. List all branches.
    2. For each branch, get the commits related.
    3. Scan the commits.
    """
    logger.info(f"Starting full background scan for {owner}/{repo}...")
    secrets = {
        "access_keys": {},
        "secret_keys": {}
    }

    async with httpx.AsyncClient() as client:
        try:
            token = await get_installation_token(client, installation_id)
            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json"
            }

            # 1. List Branches
            branches_url = f"{GITHUB_API_URL}/repos/{owner}/{repo}/branches"
            branches_resp = await http_request(client, branches_url, headers=headers)
            if branches_resp.status_code != 200:
                logger.error(f"Could not list branches for {owner}/{repo}")
                return
            
            branches = branches_resp.json()

            
            for branch in branches:
                branch_name = branch["name"]
                sha = branch["commit"]["sha"]
                logger.info(f"Scanning branch: {branch_name} ({sha})")

                # 2. Get Commits of the branch
                commits_url = f"{GITHUB_API_URL}/repos/{owner}/{repo}/commits?sha={sha}"
                commits_resp = await http_request(client, commits_url, headers=headers)
                commits = commits_resp.json()
                for commit in commits:
                    await scan_commit(client, commit["url"], headers, branch_name, secrets)

                if SPLUNK_URL and SPLUNK_TOKEN and SPLUNK_INDEX and SPLUNK_CHANNEL:
                    await generate_alerts(client, secrets, repo, owner)
                
            logger.info(f"Completed scan for {owner}/{repo}")

        except Exception as e:
            logger.error(f"Error in background scan: {e}")

# --- Routes ---

@app.get("/")
async def root():
    return {"message": "GitHub Enterprise Secret Scanner. Use /scan to trigger a full scan."}


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse(FAVICON_PATH)


@app.post("/scan")
async def scan_handler(background_tasks: BackgroundTasks):
    """
    Async endpoint to scan all repositories across all installations.
    """
    try:
        # We use a single AsyncClient context for connection pooling
        async with httpx.AsyncClient() as client:
            # 1. Retrieve all installations
            installations = await get_installations(client)
            all_repositories = {}
            
            # 2. Loop through installations (Organizations)
            for installation in installations:
                installation_id = installation["id"]
                owner = installation["account"]["login"]

                # For installation token, we need a fresh request
                # 3. Get Installation Access Token
                access_token = await get_installation_token(client, installation_id)

                # 4. List Repositories using the Token
                repo_headers = {
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github+json"
                }
                
                # Endpoint to list repos available to this installation
                repos_url = f"{GITHUB_API_URL}/installation/repositories"
                
                # Fetch all pages asynchronously
                repos_data = await get_all_pages(client, repos_url, repo_headers)
                
                # Trigger the scan for all the repositories
                repo_names = []
                for repo in repos_data:
                    repo_name = repo["name"]
                    repo_names.append(repo_name)
                    background_tasks.add_task(background_scan_all_branches, installation_id, owner, repo_name)

                all_repositories[owner] = repo_names


        return {
            "status": "scanning",
            "total_installations": len(installations),
            "data": all_repositories
        }

    except Exception as e:
        # catch-all for debugging
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/webhook")
async def webhook_handler(request: Request, background_tasks: BackgroundTasks, x_hub_signature_256: str = Header(None), x_github_event: str = Header(None)):
    """
    Handles Repository Creation and Push events to scan for secrets.
    """
    if not GITHUB_WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="GITHUB_WEBHOOK_SECRET is not configured")

    payload_body = await request.body()
    verify_webhook_signature(payload_body, GITHUB_WEBHOOK_SECRET, x_hub_signature_256)
    payload = await request.json()

    async with httpx.AsyncClient() as client:
        try:
            # We need to find the installation id corresponding to the repository
            owner_id = payload["repository"]["owner"]["id"]
            installation_id = None
            installations = await get_installations(client)

            for installation in installations:
                if owner_id == installation["account"]["id"]:
                    installation_id = installation["id"]

            if not installation_id:
                return {"status": "No installation ID found"}
            
            token = await get_installation_token(client, installation_id)
        except Exception:
            return {"status": "Failed to get auth token"}

        # CASE 1: Push Event
        if x_github_event == "push":
            secrets = {
                "access_keys": {},
                "secret_keys": {}
            }

            repo = payload["repository"]["name"]
            owner = payload["repository"]["owner"]["name"]
            branch_name = payload["ref"].rsplit("/")[-1]
            commits = payload.get("commits", [])
            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json" 
            }
            
            logger.info(f"Scanning Push to {owner}/{repo} (Branch: {branch_name}. Commits: {len(commits)})")

            # Iterate through all commits to detect secrets
            for commit in commits:
                commit_id = commit["id"]
                commit_url = f"{GITHUB_API_URL}/repos/{owner}/{repo}/commits/{commit_id}"
                await scan_commit(client, commit_url, headers, branch_name, secrets)
            
            if SPLUNK_URL and SPLUNK_TOKEN and SPLUNK_INDEX and SPLUNK_CHANNEL:
                await generate_alerts(client, secrets, repo, owner)

            return {"status": "Push Scanned"}

        # CASE 2: Repository Created
        elif x_github_event == "repository" and payload.get("action") == "created":
            repo = payload["repository"]["name"]
            owner = payload["repository"]["owner"]["name"]
            
            logger.info(f"🆕 New Repository Created: {owner}/{repo}. Starting initial scan...")
            # Trigger full scan
            background_tasks.add_task(background_scan_all_branches, installation_id, owner, repo)
            
            return {"status": "Repository creation processed - Scan started"}

    return {"status": "Event received"}
