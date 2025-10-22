
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
