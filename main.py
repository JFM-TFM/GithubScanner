import os
import time
import jwt
import httpx
import hmac
import hashlib
import re
import base64
import logging
from time import sleep
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
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET") # New configuration

# --- Regex Patterns for AWS Secrets ---
# 1. AWS Access Key ID (Standard 20-char uppercase starting with specific prefixes)
AWS_ACCESS_KEY_PATTERN = re.compile(r'(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}')
# 2. AWS Secret Access Key (40-char base64-like string)
AWS_SECRET_KEY_PATTERN = re.compile(r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])')

# --- Helper Functions ---

def get_jwt() -> str:
    if not GITHUB_APP_ID:
        raise HTTPException(status_code=500, detail="GITHUB_APP_ID not set")
    try:
        with open(GITHUB_PRIVATE_KEY_PATH, 'r') as f:
            private_key = f.read()
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail=f"Private key not found at {GITHUB_PRIVATE_KEY_PATH}")

    payload = {
        'iat': int(time.time()) - 60,
        'exp': int(time.time()) + (10 * 60),
        'iss': GITHUB_APP_ID
    }
    return jwt.encode(payload, private_key, algorithm='RS256')

async def get_installation_token(client: httpx.AsyncClient, installation_id: int) -> str:
    app_jwt = get_jwt()
    headers = {
        "Authorization": f"Bearer {app_jwt}",
        "Accept": "application/vnd.github+json"
    }
    url = f"{GITHUB_API_URL}/app/installations/{installation_id}/access_tokens"
    resp = await http_request(client, url, headers=headers, method='POST')
    if resp.status_code != 201:
        logger.error(f"Failed to get token for installation {installation_id}: {resp.text}")
        raise Exception("Failed to get installation token")
    return resp.json()['token']


async def http_request(client: httpx.AsyncClient, url: str, headers: dict, method='GET', body={}, follow_redirects=False):
    response = None
    if method == 'GET':
        response = await client.get(url, headers=headers, follow_redirects=follow_redirects)
    
    elif method == 'POST':
        response = await client.post(url, headers=headers, data=body, follow_redirects=follow_redirects)
    
    retry_after = response.headers.get('retry_after')
    # Means the rate limit has been reached
    if retry_after:
        sleep(int(retry_after) + 1)
        return await http_request(client, url, headers, method, body, follow_redirects)

    return response        


def verify_webhook_signature(payload_body: bytes, secret_token: str, signature_header: str):
    if not signature_header:
        raise HTTPException(status_code=403, detail="x-hub-signature-256 header is missing!")
    hash_object = hmac.new(secret_token.encode('utf-8'), msg=payload_body, digestmod=hashlib.sha256)
    expected_signature = "sha256=" + hash_object.hexdigest()
    if not hmac.compare_digest(expected_signature, signature_header):
        raise HTTPException(status_code=403, detail="Request signature is invalid")


def scan_text_for_secrets(text: str, source: str):
    """
    Scans a block of text for AWS secrets.
    """
    access_keys = AWS_ACCESS_KEY_PATTERN.findall(text)
    # We scan for secret keys too, but only log if we find an Access Key to reduce noise
    # or if we are very confident. For this demo, we log Access Keys found.
    
    if access_keys:
        logger.warning(f"🚨 SECRET DETECTED in {source}!")
        for key in access_keys:
            # Redact part of the key for logging
            redacted = key[:4] + "*" * 12 + key[-4:]
            logger.warning(f"   -> Found Potential AWS Access Key: {redacted}")


async def scan_diff_url(client: httpx.AsyncClient, diff_url: str, token: str, source_label: str):
    """
    Fetches the Diff from GitHub and scans added lines (+).
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3.diff" # Important to get raw diff
    }
    try:
        response = await http_request(client, diff_url, headers=headers, follow_redirects=True)
        if response.status_code == 200:
            diff_text = response.text
            # Only scan lines starting with '+' (added code)
            added_lines = "\n".join([line for line in diff_text.split('\n') if line.startswith('+') and not line.startswith('+++')])
            scan_text_for_secrets(added_lines, source_label)
        else:
            logger.error(f"Failed to fetch diff from {diff_url}: {response.status_code}")
    except Exception as e:
        logger.error(f"Error scanning diff {diff_url}: {e}")

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



# --- Background Task for Full Scan ---

async def background_scan_all_branches(installation_id: int, owner: str, repo: str):
    """
    1. List all branches.
    2. For each branch, get the Git Tree (recursive).
    3. Scan files.
    """
    logger.info(f"Starting full background scan for {owner}/{repo}...")
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
                branch_name = branch['name']
                sha = branch['commit']['sha']
                logger.info(f"Scanning branch: {branch_name} ({sha})")

                # 2. Get Tree (Recursive)
                tree_url = f"{GITHUB_API_URL}/repos/{owner}/{repo}/git/trees/{sha}?recursive=1"
                tree_resp = await http_request(client, tree_url, headers=headers)
                if tree_resp.status_code != 200:
                    continue
                
                tree_data = tree_resp.json()
                
                # 3. Iterate Files
                # Limit to 50 files for demo purposes to avoid hitting API limits
                files_to_scan = [item for item in tree_data.get('tree', []) if item['type'] == 'blob'][:50]
                
                for file_item in files_to_scan:
                    path = file_item['path']
                    blob_url = file_item['url']
                    
                    # Fetch Blob Content
                    blob_resp = await http_request(client, blob_url, headers=headers)
                    if blob_resp.status_code == 200:
                        blob_json = blob_resp.json()
                        content_b64 = blob_json.get('content', '')
                        encoding = blob_json.get('encoding')
                        
                        if encoding == 'base64' and content_b64:
                            try:
                                decoded_content = base64.b64decode(content_b64).decode('utf-8', errors='ignore')
                                scan_text_for_secrets(decoded_content, f"File: {branch_name}/{path}")
                            except Exception:
                                pass # Skip binary files or decoding errors
            
            logger.info(f"Completed scan for {owner}/{repo}")

        except Exception as e:
            logger.error(f"Error in background scan: {e}")

# --- Routes ---

@app.get("/")
async def root():
    return {"message": "GitHub Enterprise Secret Scanner. Use /scan/{owner}/{repo} to trigger a full scan."}


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse(FAVICON_PATH)


@app.post("/scan")
async def scan_all(background_tasks: BackgroundTasks):
    """
    Async endpoint to scan all repositories across all installations.
    """
    try:
        # We use a single AsyncClient context for connection pooling
        async with httpx.AsyncClient() as client:
            
            # 1. Authenticate as the App to find installations
            app_jwt = get_jwt()
            app_headers = {
                "Authorization": f"Bearer {app_jwt}",
                "Accept": "application/vnd.github+json"
            }
            
            # Get installations (This endpoint is paginated too, but typically small enough for one call.
            # ideally, use get_all_pages here too if you have > 100 orgs)
            install_response = await http_request(client, f"{GITHUB_API_URL}/app/installations", headers=app_headers)
            
            if install_response.status_code != 200:
                raise HTTPException(status_code=install_response.status_code, detail=install_response.text)
                
            installations = install_response.json()
            all_repositories = {}
            
            # 2. Loop through installations (Organizations)
            for install in installations:
                install_id = install["id"]
                owner = install["account"]["login"]

                # For installation token, we need a fresh request
                # 3. Get Installation Access Token
                token_url = f"{GITHUB_API_URL}/app/installations/{install_id}/access_tokens"
                token_res = await http_request(client, token_url, headers=app_headers, method='POST')

                # Ignore the accounts that return error                
                if token_res.status_code != 201:
                    logger.error(f"Could not get token for organization {owner}")
                    continue
                    
                access_token = token_res.json()["token"]
                
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
                    background_tasks.add_task(background_scan_all_branches, install_id, owner, repo_name)

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
    Handles Pull Request and Push events to scan for secrets.
    """
    if not GITHUB_WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="GITHUB_WEBHOOK_SECRET is not configured")

    payload_body = await request.body()
    verify_webhook_signature(payload_body, GITHUB_WEBHOOK_SECRET, x_hub_signature_256)
    
    payload = await request.json()
    
    # We need an installation token to fetch diffs
    if 'installation' in payload:
        installation_id = payload['installation']['id']
    else:
        return {"status": "No installation ID found"}

    async with httpx.AsyncClient() as client:
        try:
            token = await get_installation_token(client, installation_id)
        except Exception:
            return {"status": "Failed to get auth token"}

        # CASE 1: Pull Request
        if x_github_event == 'pull_request' and payload.get('action') in ['opened', 'synchronize']:
            pr = payload['pull_request']
            diff_url = pr['diff_url']
            pr_title = pr['title']
            
            logger.info(f"Scanning PR: {pr_title}")
            await scan_diff_url(client, diff_url, token, f"PR: {pr_title}")
            return {"status": "PR Scanned"}

        # CASE 2: Push Event
        elif x_github_event == 'push':
            repo_full_name = payload['repository']['full_name']
            ref = payload['ref'] # e.g., refs/heads/main
            commits = payload.get('commits', [])
            
            logger.info(f"Scanning Push to {repo_full_name} ({len(commits)} commits)")
            
            # Optimization: If many commits, use the 'compare' URL
            before = payload.get('before')
            after = payload.get('after')
            
            if before and after and not re.match(r'^0+$', before):
                # Standard push
                compare_url = f"{GITHUB_API_URL}/repos/{repo_full_name}/compare/{before}...{after}"
                # Note: The API returns JSON for compare, we need the diff format.
                # Use the headers to request the diff format from the compare endpoint is tricky.
                # Easier to iterate commits or use the diff_url provided in the commit object.
                pass 

            # Simple approach: Iterate up to 5 commits to avoid timeouts
            for commit in commits[:5]:
                commit_id = commit['id']
                # The payload usually doesn't have the diff_url directly usable without auth headers
                # Construct the commit URL
                # "https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
                commit_url = f"{GITHUB_API_URL}/repos/{repo_full_name}/commits/{commit_id}"
                
                # Fetch the diff for this commit
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github.v3.diff" 
                }
                resp = await http_request(client, commit_url, headers=headers)
                if resp.status_code == 200:
                    diff_text = resp.text
                    added_lines = "\n".join([l for l in diff_text.split('\n') if l.startswith('+') and not l.startswith('+++')])
                    scan_text_for_secrets(added_lines, f"Commit {commit_id[:7]}")

            return {"status": "Push Scanned"}

        # CASE 3: Repository Created
        elif x_github_event == 'repository' and payload.get('action') == 'created':
            repo_full_name = payload['repository']['full_name']
            owner, repo_name = repo_full_name.split('/')
            
            logger.info(f"🆕 New Repository Created: {repo_full_name}. Starting initial scan...")
            # Trigger full scan of default branch
            background_tasks.add_task(background_scan_all_branches, installation_id, owner, repo_name)
            
            return {"status": "Repository creation processed - Scan started"}

    return {"status": "Event received"}
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)