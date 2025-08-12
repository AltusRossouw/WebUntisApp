#!/usr/bin/env python3
"""
Login to WebUntis using details extracted from a captured requests folder (e.g. a HAR export).

This script attempts to:
  1) Parse a HAR or JSON file in the given directory for a getUserData2017 request
  2) Perform getUserData2017 to establish a session (JSESSIONID)
  3) Perform getAuthToken to retrieve a JWT
  4) Call the REST mobile data endpoint to verify the token

Sensitive values are not logged. Use at your own risk and comply with WebUntis' terms.

Usage:
  python scripts/webuntis_login.py --dir "./Webuntis requests/app.folder"
  python scripts/webuntis_login.py --dir "./app.folder"

Overrides (if parsing fails):
  --base-host kos.webuntis.com --school-login eduvos-campus --tenant-id 123 --schoolname-b64 ZWR1dm9zLWNhbXB1cw== --user alice --otp 123456

Requires: requests
"""

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qs

import requests


@dataclass
class AuthDetails:
    base_host: str
    school_login: str
    tenant_id: str
    schoolname_b64: str
    user: str
    otp: int
    client_time: int


def _parse_cookie_header(cookie_value: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for part in cookie_value.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"')
            out[k] = v
    return out


def _extract_from_har_entry(entry: dict) -> Optional[Tuple[AuthDetails, Dict[str, str]]]:
    """Return (AuthDetails, headers) if this HAR entry is getUserData2017."""
    req = entry.get("request", {})
    url = req.get("url", "")
    if "getUserData2017" not in url:
        return None

    headers_list = req.get("headers", [])
    headers = {h.get("name"): h.get("value") for h in headers_list if "name" in h}
    cookie_header = headers.get("Cookie", "") or headers.get("cookie", "")
    cookies = _parse_cookie_header(cookie_header) if cookie_header else {}

    post = req.get("postData", {})
    body_text = post.get("text") or ""
    try:
        body = json.loads(body_text)
    except Exception:
        return None

    params = (body.get("params") or [{}])[0]
    auth = params.get("auth") or {}
    user = auth.get("user")
    otp = auth.get("otp")
    client_time = auth.get("clientTime")

    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    school_login = (qs.get("school") or [""])[0]
    s_host = (qs.get("s") or [""])[0]

    base_host = s_host or parsed.netloc
    tenant_id = cookies.get("Tenant-Id") or cookies.get("TenantId") or ""
    schoolname_b64 = cookies.get("schoolname") or ""

    if not (base_host and school_login and user and otp and client_time and schoolname_b64 and tenant_id):
        return None

    try:
        otp_int = int(otp)
        client_time_int = int(client_time)
    except Exception:
        return None

    details = AuthDetails(
        base_host=base_host,
        school_login=school_login,
        tenant_id=str(tenant_id),
        schoolname_b64=str(schoolname_b64),
        user=str(user),
        otp=otp_int,
        client_time=client_time_int,
    )
    return details, headers


def _parse_text_capture_file(file_path: Path) -> Optional[AuthDetails]:
    """Parse a text capture file in the format observed from the app.folder."""
    try:
        with file_path.open("r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        return None

    # Check if this is a getUserData2017 request
    if "getUserData2017" not in content:
        return None

    lines = content.strip().split('\n')
    
    # Parse the first line for URL info
    first_line = lines[0] if lines else ""
    url_match = re.search(r'POST (/[^\s]+)', first_line)
    if not url_match:
        return None
    
    url_path = url_match.group(1)
    
    # Extract query parameters from URL
    parsed = urlparse(url_path)
    qs = parse_qs(parsed.query)
    school_login = (qs.get("school") or [""])[0]
    s_host = (qs.get("s") or [""])[0]
    
    # Parse headers to find Cookie and Host
    base_host = ""
    cookies = {}
    body_started = False
    body_lines = []
    
    for line in lines[1:]:
        if not body_started and line.strip() == "":
            body_started = True
            continue
        
        if body_started:
            body_lines.append(line)
        elif line.startswith("Host: "):
            base_host = line[6:].strip()
        elif line.startswith("Cookie: "):
            cookie_header = line[8:].strip()
            cookies = _parse_cookie_header(cookie_header)
    
    # Use s_host from query params if available, otherwise use Host header
    if s_host:
        base_host = s_host
    
    # Parse JSON body
    body_text = '\n'.join(body_lines).strip()
    try:
        body = json.loads(body_text)
    except Exception:
        return None
    
    params = (body.get("params") or [{}])[0]
    auth = params.get("auth") or {}
    user = auth.get("user")
    otp = auth.get("otp")
    client_time = auth.get("clientTime")
    
    tenant_id = cookies.get("Tenant-Id") or ""
    schoolname_b64 = cookies.get("schoolname") or ""
    
    # Clean up schoolname_b64 - remove leading underscore if present
    if schoolname_b64.startswith("_"):
        schoolname_b64 = schoolname_b64[1:]
    
    if not (base_host and school_login and user and otp and client_time and schoolname_b64 and tenant_id):
        return None
    
    try:
        otp_int = int(otp)
        client_time_int = int(client_time)
    except Exception:
        return None
    
    return AuthDetails(
        base_host=base_host,
        school_login=school_login,
        tenant_id=str(tenant_id),
        schoolname_b64=str(schoolname_b64),
        user=str(user),
        otp=otp_int,
        client_time=client_time_int,
    )


def _find_details_in_dir(dir_path: Path) -> Optional[AuthDetails]:
    # 1) Try HAR files
    for p in dir_path.rglob("*.har"):
        try:
            with p.open("r", encoding="utf-8") as f:
                har = json.load(f)
            entries = (har.get("log") or {}).get("entries") or []
            for e in entries:
                res = _extract_from_har_entry(e)
                if res:
                    details, _ = res
                    return details
        except Exception:
            continue

    # 2) Try text capture files (like the app.folder format)
    for p in dir_path.rglob("*.txt"):
        details = _parse_text_capture_file(p)
        if details:
            return details

    # 3) Try generic JSON request dumps (array or object)
    for p in dir_path.rglob("*.json"):
        try:
            with p.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue

        def try_one(obj: dict) -> Optional[AuthDetails]:
            if not isinstance(obj, dict):
                return None
            if obj.get("method") != "getUserData2017":
                return None
            # Try to reconstruct base_host, school, and cookies if present
            url = obj.get("url") or ""
            base_host = ""
            school_login = ""
            tenant_id = ""
            schoolname_b64 = ""

            if url:
                u = urlparse(url)
                qs = parse_qs(u.query)
                school_login = (qs.get("school") or [""])[0]
                base_host = (qs.get("s") or [""])[0] or u.netloc

            headers = {}
            for k in ("headers", "requestHeaders"):
                if k in obj and isinstance(obj[k], dict):
                    headers = obj[k]
                    break

            cookie_header = headers.get("Cookie") or headers.get("cookie") or ""
            cookies = _parse_cookie_header(cookie_header) if cookie_header else {}
            tenant_id = cookies.get("Tenant-Id") or ""
            schoolname_b64 = cookies.get("schoolname") or ""

            params = (obj.get("params") or [{}])[0]
            auth = params.get("auth") or {}
            user = auth.get("user")
            otp = auth.get("otp")
            client_time = auth.get("clientTime")
            if not (base_host and school_login and user and otp and client_time and schoolname_b64 and tenant_id):
                return None
            return AuthDetails(
                base_host=base_host,
                school_login=school_login,
                tenant_id=str(tenant_id),
                schoolname_b64=str(schoolname_b64),
                user=str(user),
                otp=int(otp),
                client_time=int(client_time),
            )

        if isinstance(data, dict):
            res = try_one(data)
            if res:
                return res
        if isinstance(data, list):
            for obj in data:
                res = try_one(obj)
                if res:
                    return res

    return None


def _jsonrpc_payload(method: str, auth: AuthDetails, extra: Optional[dict] = None) -> dict:
    params = {"auth": {"user": auth.user, "otp": auth.otp, "clientTime": auth.client_time}}
    if extra:
        params.update(extra)
    return {"jsonrpc": "2.0", "id": "UntisMobileiOS", "method": method, "params": [params]}


def login_flow(auth: AuthDetails) -> None:
    s = requests.Session()
    # Set initial cookies
    s.cookies.set("Tenant-Id", auth.tenant_id)
    s.cookies.set("schoolname", auth.schoolname_b64)

    base = f"https://{auth.base_host}"

    def rpc_url(method: str) -> str:
        return f"{base}/WebUntis/jsonrpc_intern.do?a=0&m={method}&s={auth.base_host}&school={auth.school_login}&v=i4.1.0"

    # 1) getUserData2017
    print("Step 1: getUserData2017 ...")
    r1 = s.post(rpc_url("getUserData2017"), json=_jsonrpc_payload("getUserData2017", auth), timeout=20)
    print(f"  Status: {r1.status_code}")
    if r1.status_code != 200:
        print("  ERROR: getUserData2017 failed.")
        print(f"  Response: {r1.text[:500]}...")
        sys.exit(1)
    # Avoid printing PII: just confirm session cookie present
    got_jsession = "JSESSIONID" in s.cookies.get_dict()
    print(f"  Session established: {'yes' if got_jsession else 'no'}")

    # 2) getAuthToken
    print("Step 2: getAuthToken ...")
    r2 = s.post(rpc_url("getAuthToken"), json=_jsonrpc_payload("getAuthToken", auth), timeout=20)
    print(f"  Status: {r2.status_code}")
    token = None
    try:
        j = r2.json()
        token = (((j or {}).get("result") or {}).get("token"))
    except Exception:
        pass
    if not token:
        print("  ERROR: No token returned.")
        print(f"  Response: {r2.text[:500]}...")
        sys.exit(1)
    print(f"  Token acquired: yes (len={len(token)})")

    # 3) Mobile data
    print("Step 3: GET v3/mobile/data ...")
    h = {"Authorization": f"Bearer {token}"}
    r3 = s.get(f"{base}/WebUntis/api/rest/view/v3/mobile/data", headers=h, timeout=20)
    print(f"  Status: {r3.status_code}")
    try:
        j = r3.json()
        user_id = (((j or {}).get("user") or {}).get("person") or {}).get("id")
    except Exception:
        user_id = None
    if user_id is not None:
        print(f"  Verified user person.id: {user_id}")
    else:
        print("  WARNING: Could not parse person.id")
        print(f"  Response: {r3.text[:200]}...")

    print("Done.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", default=None, help="Directory containing HAR/JSON request captures")
    parser.add_argument("--base-host", default=None)
    parser.add_argument("--school-login", default=None)
    parser.add_argument("--tenant-id", default=None)
    parser.add_argument("--schoolname-b64", default=None)
    parser.add_argument("--user", dest="user_name", default=None)
    parser.add_argument("--otp", type=int, default=None)
    parser.add_argument("--client-time", type=int, default=None)
    args = parser.parse_args()

    # Resolve default folder
    candidate_dirs = []
    if args.dir:
        candidate_dirs.append(Path(args.dir))
    candidate_dirs.extend([
        Path("./Webuntis requests/app.folder"),
        Path("./app.folder"),
    ])

    details = None
    for d in candidate_dirs:
        if d.exists() and d.is_dir():
            details = _find_details_in_dir(d)
            if details:
                print(f"Parsed auth details from: {d}")
                break

    # Apply overrides if provided or if details are missing
    if details:
        # Apply individual overrides to existing details
        if args.base_host:
            details.base_host = args.base_host
        if args.school_login:
            details.school_login = args.school_login
        if args.tenant_id:
            details.tenant_id = args.tenant_id
        if args.schoolname_b64:
            details.schoolname_b64 = args.schoolname_b64
        if args.user_name:
            details.user = args.user_name
        if args.otp:
            details.otp = args.otp
        if args.client_time:
            details.client_time = args.client_time
        else:
            # Use current time in milliseconds if not provided
            details.client_time = int(time.time() * 1000)
    else:
        # Require mandatory fields via overrides
        if not (args.base_host and args.school_login and args.tenant_id and args.schoolname_b64 and args.user_name and args.otp):
            print("Could not parse captured requests. Provide overrides:")
            print("  --base-host --school-login --tenant-id --schoolname-b64 --user --otp")
            print("Example:")
            print("  python scripts/webuntis_login.py --base-host kos.webuntis.com --school-login eduvos-campus --tenant-id 9138900 --schoolname-b64 ZWR1dm9zLWNhbXB1cw== --user alice@example.com --otp 123456")
            sys.exit(2)
        details = AuthDetails(
            base_host=args.base_host,
            school_login=args.school_login,
            tenant_id=args.tenant_id,
            schoolname_b64=args.schoolname_b64,
            user=args.user_name,
            otp=args.otp,
            client_time=args.client_time or int(time.time() * 1000),
        )

    print("Auth details (redacted):")
    print(f"  Base host: {details.base_host}")
    print(f"  School: {details.school_login}")
    print(f"  Tenant ID: {details.tenant_id}")
    print(f"  User: {details.user[:5]}***")
    print(f"  OTP: ***{str(details.otp)[-2:]}")
    print(f"  Client time: {details.client_time}")
    print()

    login_flow(details)


if __name__ == "__main__":
    main()