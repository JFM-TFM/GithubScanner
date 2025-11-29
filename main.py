import os
import time
import jwt
import httpx
import hmac
import hashlib
from fastapi import FastAPI, HTTPException, Request, Header, status
from fastapi.responses import FileResponse
from typing import List, Dict, Any

app = FastAPI(title="GitHub Enterprise Repo Reader")

# --- Configuration ---
GITHUB_APP_ID = os.getenv("GITHUB_APP_ID")
GITHUB_API_URL = os.getenv("GITHUB_API_URL", "https://api.github.com")
GITHUB_PRIVATE_KEY_PATH = os.getenv("GITHUB_PRIVATE_KEY_PATH", "/app/certs/github.key")
FAVICON_PATH = os.getenv("FAVICON_PATH", "favicon.ico")
GITHUB_WEBHOOK_SECRET = os.getenv('GITHUB_WEBHOOK_SECRET') # New configuration


# --- Helper Functions ---

def get_jwt() -> str:
    """
    Generates a generic JWT for the App (synchronous is fine here).
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
    
    return jwt.encode(payload, private_key, algorithm="RS256")


async def get_all_pages(client: httpx.AsyncClient, url: str, headers: Dict) -> List[Any]:
    """
    Async helper to handle GitHub pagination.
    """
    results = []
    while url:
        response = await client.get(url, headers=headers)
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


def verify_webhook_signature(payload_body: bytes, secret_token: str, signature_header: str):
    """
    Verifies that the webhook request came from GitHub.
    """
    if not signature_header:
        raise HTTPException(status_code=403, detail="x-hub-signature-256 header is missing!")
    
    hash_object = hmac.new(secret_token.encode('utf-8'), msg=payload_body, digestmod=hashlib.sha256)
    expected_signature = "sha256=" + hash_object.hexdigest()
    
    if not hmac.compare_digest(expected_signature, signature_header):
        raise HTTPException(status_code=403, detail="Request signature is invalid")

# --- Routes ---

@app.get("/")
async def root():
    return {"message": "GitHub App Enterprise Reader (FastAPI). Go to /repos to list repositories."}


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse(FAVICON_PATH)


@app.get("/repos")
async def list_all_repos():
    """
    Async endpoint to fetch all repositories across all installations.
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
            install_response = await client.get(f"{GITHUB_API_URL}/app/installations", headers=app_headers)
            
            if install_response.status_code != 200:
                raise HTTPException(status_code=install_response.status_code, detail=install_response.text)
                
            installations = install_response.json()
            all_repositories = {}
            
            # 2. Loop through installations (Organizations)
            for install in installations:
                print(install)
                install_id = install["id"]
                account_login = install["account"]["login"]
                
                # RE-GENERATE JWT (or reuse if valid) - for simplicity we reuse logic
                # For installation token, we need a fresh request
                
                # 3. Get Installation Access Token
                token_url = f"{GITHUB_API_URL}/app/installations/{install_id}/access_tokens"
                token_res = await client.post(token_url, headers=app_headers)
                
                if token_res.status_code != 201:
                    all_repositories[account_login] = {"error": "Could not get token"}
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
                print(repos_data)
                
                # Extract just names for cleaner output
                repo_names = [repo["full_name"] for repo in repos_data]
                all_repositories[account_login] = repo_names
                
            return {
                "status": "success",
                "total_installations": len(installations),
                "data": all_repositories
            }
            
    except Exception as e:
        # catch-all for debugging
        raise HTTPException(status_code=500, detail=str(e))



@app.post("/webhook")
async def webhook_handler(request: Request, x_hub_signature_256: str = Header(None), x_github_event: str = Header(None)):
    """
    Handles incoming GitHub Webhooks.
    Triggers when:
    1. A Pull Request is created (opened)
    2. A Repository is created
    """
    if not GITHUB_WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="GITHUB_WEBHOOK_SECRET is not configured")

    # 1. Verify Signature
    payload_body = await request.body()
    verify_webhook_signature(payload_body, GITHUB_WEBHOOK_SECRET, x_hub_signature_256)

    # 2. Parse Payload
    payload = await request.json()
    action = payload.get('action')
    
    # 3. Handle Events based on X-GitHub-Event header
    
    # CASE A: Pull Request Opened
    if x_github_event == 'pull_request':
        if action == 'opened':
            pr = payload['pull_request']
            repo_name = payload['repository']['full_name']
            pr_title = pr['title']
            pr_user = pr['user']['login']
            pr_url = pr['html_url']
            
            print(f"🚀 NEW PR DETECTED!")
            print(f"Repo: {repo_name}")
            print(f"User: {pr_user}")
            print(f"Title: {pr_title}")
            print(f"URL: {pr_url}")
            
            return {"status": "PR processed", "pr_title": pr_title}

    # CASE B: Repository Created
    elif x_github_event == 'repository':
        if action == 'created':
            repo_name = payload['repository']['full_name']
            owner_login = payload['repository']['owner']['login']
            repo_url = payload['repository']['html_url']
            
            print(f"📦 NEW REPO CREATED!")
            print(f"Repo: {repo_name}")
            print(f"Owner: {owner_login}")
            print(f"URL: {repo_url}")
            
            return {"status": "Repository creation processed", "repo_name": repo_name}

    return {"status": f"Event '{x_github_event}' received but not processed"}
