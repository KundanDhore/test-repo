from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse
from starlette.config import Config
import httpx
import os
import re
from datetime import datetime, timedelta, timezone
from fastapi.middleware.cors import CORSMiddleware
import asyncio

app = FastAPI()


MAX_DIFF_LINES = 500
MAX_PRS_TO_CHECK = 10
SENSITIVE_PATHS = ["config", "secrets", "credentials", "keys", ".env", "dockerfile", "ci", ".github/workflows"]

origins = [
    "*", # Allow all origins during development
    # You could also restrict this to specific origins if needed:
    # "http://localhost",
    # "http://localhost:8080",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"], # Allow GET, POST, DELETE, etc.
    allow_headers=["*"],
)
config = Config(".env")
CLIENT_ID = config("GITHUB_CLIENT_ID")
CLIENT_SECRET = config("GITHUB_CLIENT_SECRET")
REDIRECT_URI = "http://localhost:8000/auth/callback"

GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_API_URL = "https://api.github.com"

SECRET_PATTERNS = {
    "AWS_ACCESS_KEY": r"(AKIA[0-9A-Z]{16})",
    "SECRET_KEY_32_CHAR_HEX": r"([0-9a-fA-F]{32})",
    "GITHUB_TOKEN_GH_PREFIX": r"(ghp_[0-9a-zA-Z]{36})",
    "GENERIC_PASSWORD": r"(?:pass|password|pwd|secret|token|key|credential)(?:[\s=:]+['\"])([a-zA-Z0-9_\-\.\/]{16,64})['\"]"
}




def analyze_content_for_secrets(file_path: str, content: str) -> list:
    """
    Analyzes content using regex patterns to find potential hardcoded secrets.
    """
    found_secrets = []
    
    for pattern_name, pattern in SECRET_PATTERNS.items():
        # Use findall to locate all matches
        # re.IGNORECASE helps catch keys like 'aPiKey'
        matches = re.findall(pattern, content, re.IGNORECASE)
        
        for match in matches:
            # Mask the secret for display, showing only the type and length
            secret_value = match[0] if isinstance(match, tuple) else match
            masked_snippet = f"Found match of type {pattern_name} (Length: {len(secret_value)})"
            
            found_secrets.append({
                "type": pattern_name,
                "file": file_path,
                "snippet": masked_snippet
            })
            
    return found_secrets

def is_path_sensitive(file_path: str) -> bool:
    """Checks if a file path matches any sensitive directory/file patterns."""
    path_lower = file_path.lower()
    return any(sens_path in path_lower for sens_path in SENSITIVE_PATHS)



@app.get("/login")
def login():
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "repo",  # scope to access repo info, adjust as needed
        "allow_signup": "true"
    }
    url = httpx.URL(GITHUB_AUTH_URL).copy_with(params=params)
    return RedirectResponse(str(url))

@app.get("/auth/callback")
async def auth_callback(code: str = None):
    if not code:
        raise HTTPException(status_code=400, detail="Code not provided")

    async with httpx.AsyncClient() as client:
        headers = {"Accept": "application/json"}
        data = {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code": code,
            "redirect_uri": REDIRECT_URI,
        }
        token_resp = await client.post(GITHUB_TOKEN_URL, headers=headers, data=data)
        token_resp.raise_for_status()
        token_json = token_resp.json()
        access_token = token_json.get("access_token")

        if not access_token:
            raise HTTPException(status_code=400, detail="Failed to get access token")

        # Use access token to get user info or repo info
        user_resp = await client.get(
            f"{GITHUB_API_URL}/user",
            headers={"Authorization": f"token {access_token}"}
        )
        user_resp.raise_for_status()
        user_data = user_resp.json()

    return {"message": "Logged in", "user": user_data, "access_token": access_token}

# You can now use the access_token to fetch collaborators for repos the user has access to
@app.get("/repos/{owner}/{repo}/collaborators")
async def get_collaborators(owner: str, repo: str, access_token: str):
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{GITHUB_API_URL}/repos/{owner}/{repo}/collaborators",
            headers={"Authorization": f"token {access_token}"}
        )
    if response.status_code == 200:
        collaborators = response.json()
        return {"count": len(collaborators), "collaborators": collaborators}
    elif response.status_code == 404:
        raise HTTPException(status_code=404, detail="Repository not found")
    else:
        raise HTTPException(status_code=response.status_code, detail="Error fetching collaborators")

@app.get("/analyze/repos/{owner}/{repo}/visibility")
async def analyze_repo_visibility(owner: str, repo: str, access_token: str):
    """
    Checks if a repository is public or private.
    """
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{GITHUB_API_URL}/repos/{owner}/{repo}",
            headers={"Authorization": f"token {access_token}"}
        )

    if response.status_code == 200:
        repo_data = response.json()
        is_private = repo_data.get("private", False)
        
        # Misconfiguration Check: Public repos often require more scrutiny.
        misconfiguration = "None"
        if not is_private:
            misconfiguration = "Repo is Public (requires review)."

        return {
            "repo": f"{owner}/{repo}",
            "is_private": is_private,
            "visibility": "Private" if is_private else "Public",
            "misconfiguration_alert": misconfiguration
        }
    elif response.status_code == 404:
        raise HTTPException(status_code=404, detail="Repository not found or access denied")
    else:
        raise HTTPException(status_code=response.status_code, detail="Error fetching repository details")

@app.get("/analyze/repos/{owner}/{repo}/branch-protection/{branch}")
async def analyze_branch_protection(owner: str, repo: str, branch: str, access_token: str):
    """
    Checks the branch protection status for a specific branch.
    Checks for required pull request reviews and status checks.
    """
    protection_url = f"{GITHUB_API_URL}/repos/{owner}/{repo}/branches/{branch}/protection"
    
    async with httpx.AsyncClient() as client:
        response = await client.get(
            protection_url,
            headers={"Authorization": f"token {access_token}", "Accept": "application/vnd.github.v3+json"}
        )

    if response.status_code == 200:
        protection_data = response.json()
        
        # Detailed Misconfiguration Check
        misconfigurations = []
        
        # Check 1: Required PR reviews
        required_reviews = protection_data.get("required_pull_request_reviews")
        if not required_reviews or required_reviews.get("required_approving_review_count", 0) < 1:
             misconfigurations.append("No Required Pull Request Reviews (high risk of direct commits).")
        
        # Check 2: Required status checks
        required_status_checks = protection_data.get("required_status_checks")
        if not required_status_checks or not required_status_checks.get("strict"):
             misconfigurations.append("Status checks are not 'strict' or not enforced.")

        return {
            "repo": f"{owner}/{repo}",
            "branch": branch,
            "protected": True,
            "details": protection_data,
            "misconfiguration_alerts": misconfigurations if misconfigurations else ["None"]
        }
    
    elif response.status_code == 404:
        # 404 typically means the branch is not protected, which is a key misconfiguration
        return {
            "repo": f"{owner}/{repo}",
            "branch": branch,
            "protected": False,
            "details": "Branch is not protected. This is a severe misconfiguration.",
            "misconfiguration_alerts": ["Branch is NOT protected. No enforcement of code quality/security."]
        }
    else:
        raise HTTPException(status_code=response.status_code, detail="Error fetching branch protection status")


@app.get("/analyze/repos/{owner}/{repo}/secrets")
async def analyze_repo_secrets(owner: str, repo: str, access_token: str):
    """
    Recursively analyzes all files in a repository for hardcoded secrets 
    using the GitHub Contents API.
    """
    all_found_secrets = []
    total_files_scanned_count = 0  # Initialize a dedicated counter for files
    
    async with httpx.AsyncClient() as client:
        headers = {"Authorization": f"token {access_token}", "Accept": "application/vnd.github.v3.raw"}
        
        # Recursive function to traverse the repository structure
        async def recursive_scan_directory(path: str):
            nonlocal total_files_scanned_count # Allows modification of the outer variable
            contents_url = f"{GITHUB_API_URL}/repos/{owner}/{repo}/contents/{path}"
            
            try:
                response = await client.get(contents_url, headers={"Authorization": f"token {access_token}"})
                response.raise_for_status()
                tree = response.json()
            except httpx.HTTPError as e:
                # Handle 404 for empty directory or permission issues
                print(f"Error fetching contents for {path}: {e}")
                return

            for item in tree:
                if item["type"] == "dir":
                    # Recursively call for directories
                    await recursive_scan_directory(item["path"])
                
                elif item["type"] == "file" and item.get("download_url"):
                    # Only check files, and only if a download_url is available
                    file_path = item["path"]
                    
                    # Fetch raw content of the file
                    try:
                        file_resp = await client.get(item["download_url"], headers=headers)
                        file_resp.raise_for_status()
                        file_content = file_resp.text
                        
                        # CORRECT: Increment the counter for every successfully fetched file
                        total_files_scanned_count += 1
                        
                        # Analyze and store results
                        secrets = analyze_content_for_secrets(file_path, file_content)
                        all_found_secrets.extend(secrets)
                        
                    except httpx.HTTPError as e:
                        # Skip files that can't be downloaded (e.g., too large)
                        print(f"Skipping file {file_path} due to error: {e}")
        
        # Start the recursive scan from the root (empty path)
        await recursive_scan_directory("")

    # Misconfiguration Check
    misconfiguration_alert = "None"
    if all_found_secrets:
        misconfiguration_alert = f"Found {len(all_found_secrets)} potential hardcoded secret(s) in code."

    return {
        "repo": f"{owner}/{repo}",
        "total_files_scanned": total_files_scanned_count, # FIXED: Now returns the correct file count
        "misconfiguration_alert": misconfiguration_alert,
        "details": all_found_secrets
    }


@app.get("/analyze/repos/{owner}/{repo}/inactive-collaborators")
async def analyze_inactive_collaborators(
    owner: str, 
    repo: str, 
    access_token: str, 
    days_threshold: int = 5 # Default to 90 days of inactivity
):
    """
    Checks for collaborators who have not committed to the repository 
    in the last `days_threshold` days.
    """
    
    async with httpx.AsyncClient() as client:
        auth_header = {"Authorization": f"token {access_token}"}
        
        # --- 1. Get all collaborators ---
        collaborators_url = f"{GITHUB_API_URL}/repos/{owner}/{repo}/collaborators"
        try:
            collab_resp = await client.get(collaborators_url, headers=auth_header)
            collab_resp.raise_for_status()
            collaborators_data = collab_resp.json()
        except httpx.HTTPError as e:
            raise HTTPException(status_code=collab_resp.status_code, detail=f"Error fetching collaborators: {e}")

        all_collaborators = {collab['login']: collab for collab in collaborators_data}
        collaborator_logins = set(all_collaborators.keys())
        
        # --- 2. Calculate the commit cutoff date ---
        today = datetime.now(timezone.utc)
        cutoff_date = today - timedelta(days=days_threshold)
        since_date_iso = cutoff_date.isoformat().replace("+00:00", "Z")
        
        # --- 3. Get recent commits (since the cutoff date) ---
        commits_url = f"{GITHUB_API_URL}/repos/{owner}/{repo}/commits"
        recent_commit_authors = set()
        
        # NOTE: We may need to paginate if there are thousands of commits in 90 days
        # For simplicity, we assume the first page of commits is sufficient for most repos.
        params = {"since": since_date_iso, "per_page": 100} 
        
        try:
            commit_resp = await client.get(commits_url, headers=auth_header, params=params)
            commit_resp.raise_for_status()
            commits_data = commit_resp.json()
        except httpx.HTTPError as e:
            # Commits may not be available for an empty repo, which is fine
            commits_data = [] 

        # Extract unique commit authors who have pushed since the cutoff
        for commit in commits_data:
            author = commit.get('author')
            if author and author.get('login'):
                recent_commit_authors.add(author['login'])

        # --- 4. Compare and identify inactive collaborators ---
        
        # Collaborators who have access but are NOT in the recent commit author set
        inactive_logins = collaborator_logins - recent_commit_authors
        
        inactive_collaborators = [
            {
                "login": login,
                "id": all_collaborators[login].get('id'),
                "role": all_collaborators[login].get('role_name', 'collaborator'),
                "url": all_collaborators[login].get('html_url')
            }
            for login in inactive_logins
        ]

        # --- 5. Generate Misconfiguration Alert ---
        misconfiguration_alert = "None"
        if inactive_collaborators:
            misconfiguration_alert = f"Found {len(inactive_collaborators)} inactive collaborator(s) with repo access."

        return {
            "repo": f"{owner}/{repo}",
            "inactivity_threshold_days": days_threshold,
            "total_collaborators": len(collaborator_logins),
            "inactive_collaborators_count": len(inactive_collaborators),
            "misconfiguration_alert": misconfiguration_alert,
            "details": inactive_collaborators
        }

@app.delete("/action/repos/{owner}/{repo}/collaborators/{username}")
async def revoke_collaborator_access(owner: str, repo: str, username: str, access_token: str):
    """
    Revokes access for a specific collaborator by removing them from the repository.
    This requires the authenticated user to have admin access to the repository.
    """
    
    removal_url = f"{GITHUB_API_URL}/repos/{owner}/{repo}/collaborators/{username}"
    auth_header = {"Authorization": f"token {access_token}"}
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.delete(removal_url, headers=auth_header)
            
            # GitHub returns 204 No Content upon successful removal
            if response.status_code == 204:
                return {
                    "status": "Success",
                    "message": f"Successfully revoked access for user '{username}' from repository '{owner}/{repo}'.",
                    "username": username
                }
            
            # Handle permissions errors or non-existent user
            elif response.status_code == 404:
                raise HTTPException(
                    status_code=404, 
                    detail=f"User '{username}' is not a collaborator, or the repository was not found."
                )
            
            elif response.status_code == 403:
                raise HTTPException(
                    status_code=403, 
                    detail="Forbidden: Authenticated user does not have admin permissions to remove collaborators."
                )
            
            # Handle other GitHub API errors
            else:
                response_json = response.json()
                error_message = response_json.get("message", "Unknown API error.")
                raise HTTPException(
                    status_code=response.status_code, 
                    detail=f"Failed to revoke access: {error_message}"
                )

        except httpx.HTTPError as e:
            # Handle network/connection errors
            raise HTTPException(status_code=500, detail=f"HTTP request error during revocation: {e}")


@app.get("/analyze/repos/{owner}/{repo}/all")
async def analyze_all(owner: str, repo: str, access_token: str, branch: str = "main", days_threshold: int = 90):
    """
    Runs all security analysis checks concurrently and consolidates the results.
    """
    
    # 1. Prepare coroutines (tasks to run concurrently)
    tasks = [
        analyze_repo_visibility(owner, repo, access_token),
        analyze_branch_protection(owner, repo, branch, access_token),
        analyze_repo_secrets(owner, repo, access_token),
        analyze_inactive_collaborators(owner, repo, access_token, days_threshold),
    ]

    # 2. Run concurrently and catch exceptions at the top level
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # 3. Consolidate results and status
    consolidated_results = {
        "repo": f"{owner}/{repo}",
        "summary": "Full security scan complete.",
        "results": {}
    }
    
    misconfiguration_count = 0
    full_misconfiguration_list = []

    analysis_names = ["visibility", "branch_protection", "secrets_scan", "inactive_collaborators"]
    
    for name, result in zip(analysis_names, results):
        if isinstance(result, HTTPException):
            # Handle API errors that were raised as HTTPExceptions
            consolidated_results["results"][name] = {
                "status": "Error",
                "misconfiguration_alert": f"API Error ({result.status_code}): {result.detail}",
                "details": {}
            }
            misconfiguration_count += 1
            full_misconfiguration_list.append(f"[{name}] API Error")
        else:
            # Handle successful results
            consolidated_results["results"][name] = result
            
            # Check the misconfiguration alert from the successful result
            alert = result.get("misconfiguration_alert")
            
            # Note: branch_protection returns a list, others return a string
            if isinstance(alert, list):
                if not (len(alert) == 1 and alert[0] == "None"):
                     misconfiguration_count += len(alert)
                     full_misconfiguration_list.extend([f"[{name}] {a}" for a in alert])
            elif alert and alert != "None":
                misconfiguration_count += 1
                full_misconfiguration_list.append(f"[{name}] {alert}")

    
    # 4. Final summary alert
    if misconfiguration_count > 0:
        consolidated_results["summary_alert"] = f"HIGH RISK: Found {misconfiguration_count} misconfiguration(s) across {len(results)} checks."
    else:
        consolidated_results["summary_alert"] = "LOW RISK: All major security checks passed."
        
    consolidated_results["full_alerts"] = full_misconfiguration_list

    return consolidated_results


@app.get("/analyze/repos/{owner}/{repo}/risky-prs")
async def analyze_risky_prs(owner: str, repo: str, access_token: str):
    """
    Checks the first 10 open pull requests for high-risk attributes: 
    large diffs, no reviewers, sensitive file changes, and unsigned commits.
    """
    risky_prs = []
    auth_header = {"Authorization": f"token {access_token}", "Accept": "application/vnd.github.v3+json"}

    async with httpx.AsyncClient() as client:
        # 1. Fetch open PRs
        pulls_url = f"{GITHUB_API_URL}/repos/{owner}/{repo}/pulls"
        try:
            pulls_resp = await client.get(pulls_url, headers=auth_header, params={"state": "open", "per_page": MAX_PRS_TO_CHECK})
            pulls_resp.raise_for_status()
            pulls_data = pulls_resp.json()
        except httpx.HTTPError as e:
            # Return empty list if no PRs are found or access issue
            print(f"Error fetching pull requests: {e}")
            return {
                "repo": f"{owner}/{repo}",
                "total_open_prs_checked": 0,
                "risky_prs_count": 0,
                "misconfiguration_alert": f"Error fetching PRs: {e.response.status_code}",
                "details": []
            }

        async def check_single_pr(pr):
            pr_risks = []
            
            # --- Check 1: No Reviewers ---
            # Checks if no reviewers are explicitly requested AND no reviews have been submitted
            if not pr.get("requested_reviewers") and pr.get("review_comments", 0) == 0:
                pr_risks.append("No Reviewers Assigned")

            # Initialize variables for other checks
            diff_lines = pr.get("additions", 0) + pr.get("deletions", 0)
            sensitive_files_changed = []
            
            # --- Concurrent Checks for Files and Commits ---
            # We need the files list for sensitive path checking
            files_url = f"{GITHUB_API_URL}/repos/{owner}/{repo}/pulls/{pr['number']}/files"
            head_sha = pr["head"]["sha"]
            commit_url = f"{GITHUB_API_URL}/repos/{owner}/{repo}/commits/{head_sha}"

            files_task = client.get(files_url, headers=auth_header)
            commit_task = client.get(commit_url, headers=auth_header)

            files_resp, commit_resp = await asyncio.gather(files_task, commit_task, return_exceptions=True)

            # --- Check 4: Sensitive Files Changed ---
            if not isinstance(files_resp, Exception) and files_resp.status_code == 200:
                for file in files_resp.json():
                    if is_path_sensitive(file["filename"]):
                        sensitive_files_changed.append(file["filename"])
            
            if sensitive_files_changed:
                pr_risks.append(f"Sensitive Files Changed ({', '.join(sensitive_files_changed[:2])}{'...' if len(sensitive_files_changed) > 2 else ''})")
            
            # --- Check 2: Large Diff ---
            if diff_lines > MAX_DIFF_LINES:
                pr_risks.append(f"Large Diff ({diff_lines} lines)")

            # --- Check 3: Unsigned Commits ---
            if not isinstance(commit_resp, Exception) and commit_resp.status_code == 200:
                commit_data = commit_resp.json()
                verification = commit_data.get("verification", {})
                
                # Check for unverified status
                if verification.get("verified") is False:
                    pr_risks.append("Unsigned/Unverified Head Commit")

            if pr_risks:
                risky_prs.append({
                    "number": pr["number"],
                    "title": pr["title"],
                    "url": pr["html_url"],
                    "author": pr["user"]["login"],
                    "risks": pr_risks,
                })
            
            return pr_risks

        # Execute all PR checks concurrently
        await asyncio.gather(*[check_single_pr(pr) for pr in pulls_data])

    misconfiguration_alert = "None"
    if risky_prs:
        misconfiguration_alert = f"Found {len(risky_prs)} open Pull Request(s) with security risks."

    return {
        "repo": f"{owner}/{repo}",
        "total_open_prs_checked": len(pulls_data),
        "risky_prs_count": len(risky_prs),
        "misconfiguration_alert": misconfiguration_alert,
        "details": risky_prs
    }
