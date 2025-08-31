from fastapi import FastAPI, Request
from dotenv import load_dotenv
from openai import OpenAI
import hmac
import hashlib
import requests
import os
import time
import jwt
import json
import base64

load_dotenv()

GITHUB_APP_ID = os.getenv("GITHUB_APP_ID")
GITHUB_INSTALLATION_ID = os.getenv("GITHUB_INSTALLATION_ID")
GITHUB_PRIVATE_KEY_PATH = os.getenv("GITHUB_PRIVATE_KEY_PATH")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")
OPEN_AI_API_KEY = os.getenv("OPEN_AI_API_KEY")


app = FastAPI()
client = OpenAI(api_key=OPEN_AI_API_KEY)


def verify_signature(request: Request, payload: bytes):
    signature = request.headers.get("X-Hub-Signature-256")
    if not signature:
        return False
    sha_type, sha_signature = signature.split("=")
    mac = hmac.new(GITHUB_WEBHOOK_SECRET.encode(), payload, hashlib.sha256)
    return hmac.compare_digest(mac.hexdigest(), sha_signature)


def generate_jwt():
    with open(GITHUB_PRIVATE_KEY_PATH, "r") as f:
        private_key = f.read()
    payload = {
        "iat": int(time.time()),
        "exp": int(time.time()) + (10 * 60),
        "iss": GITHUB_APP_ID,
    }
    return jwt.encode(payload, private_key, algorithm="RS256")


def get_installation_token():
    jwt_token = generate_jwt()
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/vnd.github+json",
    }
    url = f"https://api.github.com/app/installations/{GITHUB_INSTALLATION_ID}/access_tokens"
    resp = requests.post(url, headers=headers)
    resp.raise_for_status()
    return resp.json()["token"]


def post_pr_comment(repo: str, pr_number: int, comment: str, token: str):
    """Post a comment to a PR via GitHub API"""
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
    }
    formatted = f"""## 🤖 AI Code Review Suggestions

{comment.strip()}

---

_This review was generated automatically by an AI assistant._
"""
    data = {"body": formatted}
    resp = requests.post(url, headers=headers, json=data)
    resp.raise_for_status()
    return resp.json()


def post_inline_comment(
    repo: str,
    pr_number: int,
    commit_id: str,
    token: str,
    rules: str,
):
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3.diff",
    }
    diff_url = f"https://api.github.com/repos/{repo}/commits/{commit_id}"
    diff_response = requests.get(diff_url, headers=headers)
    diff_text = diff_response.text

    file_diffs = diff_text.split("diff --git ")
    for file_diff in file_diffs[1:]:
        file_header, *patch_lines = file_diff.split("\n")
        patch = "\n".join(patch_lines)

        system_prompt = f"""
        You are a strict and thorough code review assistant.
        Your goal is to review GitHub pull request diffs with as much detail as possible. 
        You MUST follow the review rules provided in JSON below when analyzing diffs:

        RULES_JSON:
        {rules}

        Requirements:
        - Output ONLY JSON with this format: [{{ "path": str, "line": int, "severity": str, "body": str }}].
        - Severity must be one of: 🟥 HIGH, 🟧 MEDIUM, 🟩 LOW.
        - For each comment, if a rule is violated, explicitly mention it using backticks with the format: Violation of `rule` (e.g., `security.no_hardcoded_secrets`).
        - Use actionable language with specific fixes.
        - Wrap code snippets in Markdown triple backticks.
        - If no issues found, reply ONLY with: "NO_ISSUES".
        - Ignore trivial cosmetic diffs unless they violate the rules.
        """.strip()
        ai_response = client.chat.completions.create(
            model="gpt-5-mini",
            messages=[
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {
                    "role": "user",
                    "content": f"Review this file diff:\n{patch}",
                },
            ],
        )
        ai_response_text = ai_response.choices[0].message.content.strip()
        if ai_response_text.strip() == "NO_ISSUES":
            print("✅ No issues found by AI, skipping inline comments.")
            return

        try:
            comments = json.loads(ai_response_text)
        except json.JSONDecodeError:
            print("❌ AI response is not valid JSON:", ai_response_text)
            return

        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
        }

        for c in comments:
            path = c.get("path")
            line = c.get("line")
            body = c.get("body")
            severity = c.get("severity", "🟧 MEDIUM")

            if not path or not line or not body:
                print(f"⚠️ Skipping invalid comment: {c}")
                continue

            payload = {
                "body": f"**Severity: {severity}**\n\n{body}\n\n---\n_This comment was generated automatically by an AI assistant._",
                "commit_id": commit_id,
                "path": path,
                "side": "RIGHT",
                "line": line,
            }

            url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/comments"
            resp = requests.post(url, headers=headers, json=payload)

            if resp.status_code >= 300:
                print(
                    f"❌ Failed to post comment on {path}:{line} -> {resp.status_code} {resp.text}"
                )
            else:
                print(f"💬 Comment posted on {path}:{line}")


def post_overall_comment(repo: str, pr_number: int, token: str, rules: str):
    diff_url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3.diff",
    }

    diff_response = requests.get(diff_url, headers=headers)
    diff_text = diff_response.text

    print(f"PR #{pr_number} in {repo} - diff content:\n")
    print(diff_text[:3000])

    system_prompt = f"""
    You are a code review assistant. 
    Follow these review rules strictly when analyzing the diff:

    RULES_JSON:
    {rules}

    Instructions:
    - Only provide actionable code review feedback.
    - Do NOT include optional suggestions unrelated to rules.
    - Always format code in Markdown blocks with syntax highlighting, like ```python ... ```.
    - If a rule is violated, explicitly mention it using backticks with the format: Violation of `rule` (e.g., `security.no_hardcoded_secrets`).
    - Use this structure:

    ## ✅ Strengths
    - ...

    ## ⚠️ Issues
    - **[🟥 HIGH]** ...
    - **[🟧 MEDIUM]** ...
    - **[🟩 LOW]** ...

    ## 💡 Suggestions
    - ...
    """.strip()

    ai_response = client.chat.completions.create(
        model="gpt-5-mini",
        messages=[
            {
                "role": "system",
                "content": system_prompt,
            },
            {
                "role": "user",
                "content": f"Review this PR diff and suggest improvements:\n{diff_text}",
            },
        ],
    )

    ai_suggestions = ai_response.choices[0].message.content
    post_pr_comment(repo, pr_number, ai_suggestions, token)


def load_rules_from_repo(repo: str, token: str, branch: str = "main"):
    url = f"https://api.github.com/repos/{repo}/contents/.pwconfig.json?ref={branch}"
    headers = {"Authorization": f"token {token}"}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        file_data = response.json()

        decoded = base64.b64decode(file_data["content"]).decode("utf-8")
        print("Getting rules from user")
        return json.loads(decoded)

    if os.path.exists(".pwconfig.json"):
        with open(".pwconfig.json", "r") as f:
            print("Getting rules from default")
            return json.load(f)

    return {"rules": {}}


@app.post("/webhook")
async def github_webhook(request: Request):
    payload = await request.body()
    if not verify_signature(request, payload):
        return {"status": "invalid signature"}

    data = await request.json()
    event = request.headers.get("X-GitHub-Event")

    if event == "pull_request" and data["action"] in ["opened", "synchronize"]:
        pr_number = data["number"]
        repo = data["repository"]["full_name"]
        commit_id = data["pull_request"]["head"]["sha"]

        token = get_installation_token()
        rules_config = load_rules_from_repo(repo=repo, token=token)
        rules = json.dumps(rules_config, indent=2)
        print(rules)
        post_inline_comment(
            repo=repo,
            pr_number=pr_number,
            commit_id=commit_id,
            token=token,
            rules=rules,
        )
        post_overall_comment(repo=repo, pr_number=pr_number, token=token, rules=rules)

    return {"status": "ok"}
