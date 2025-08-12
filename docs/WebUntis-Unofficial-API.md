# WebUntis Mobile (Unofficial) – Reverse‑Engineered API Notes

These notes are derived from the captured requests in `Webuntis requests/app.folder`. Values below use placeholders to avoid exposing credentials or PII.

Use responsibly and in accordance with WebUntis' terms of service.

## Hosts and base paths

- WebUntis (school server): https://{{baseHost}} (example observed: kos.webuntis.com)
- JSON-RPC endpoint: /WebUntis/jsonrpc_intern.do
- REST endpoints: /WebUntis/api/rest/view/...
- Push service: https://push.webuntis.com/api

School login (observed): eduvos-campus → Base64("eduvos-campus") = ZWR1dm9zLWNhbXB1cw==

## Required cookies and headers

Most calls include:

- Cookies
  - Tenant-Id="<TENANT_ID>" (e.g., "9138900")
  - schoolname="<BASE64_SCHOOL_LOGIN>" (e.g., "ZWR1dm9zLWNhbXB1cw==")
  - JSESSIONID=<SESSION_ID> (set after first successful call)
  - traceId=<TRACE> (optional; often set by server)

- Common headers
  - Content-Type: application/json (for JSON-RPC)
  - Authorization: Bearer <JWT> (for REST and push calls after obtaining token)
  - User-Agent: Untis/4.x (a realistic UA seems accepted)
  - Accept-Language: en-US;q=1.0

## Session and auth flow (observed)

1) Bootstrap session with JSON-RPC getUserData2017
- Purpose: initializes session; server sets JSESSIONID and traceId cookies.
- Request (JSON-RPC with query params on URL):
  - a=0
  - m=getUserData2017
  - s={{baseHost}}
  - school={{schoolLogin}}
  - v=i4.1.0 (app version string; observed value)

- Body parameters
  - auth.user: "<USERNAME>"
  - auth.otp: <OTP_CODE> (6 digits; app-provided)
  - auth.clientTime: <EPOCH_MS> (milliseconds since epoch)

- Response: user data (not included here) and Set-Cookie with JSESSIONID.

2) Retrieve a JWT with JSON-RPC getAuthToken
- Purpose: obtain Bearer token for REST and push API.
- Method: getAuthToken
- Body includes same auth object as above.
- Response: { result: { token: "<JWT>" } } (JWT is RS256; contains claims like tenant_id, sub, roles, locale, etc.)

3) Use REST endpoints with Bearer token
- Include Authorization: Bearer <JWT> and existing cookies.

4) JSON-RPC functional calls (e.g., getTimetable2017) continue to use cookies and the same auth object; include your personId/studentId as needed.

Note: OTP values in the captures changed over time; treat it as time-sensitive or session-bound.

## JSON-RPC methods

Base: https://{{baseHost}}/WebUntis/jsonrpc_intern.do?a=0&m=<METHOD>&s={{baseHost}}&school={{schoolLogin}}&v=i4.1.0

Include cookies Tenant-Id and schoolname at minimum. After step 1, also include JSESSIONID (and traceId if set).

- getUserData2017
  - params: [{ auth: { user, otp, clientTime } }]
  - Returns user and master data; sets session cookies.

- getColors2017
  - params: [{ auth: { user, otp, clientTime } }]
  - Returns color configuration for lesson types (FREE, LESSON, EXAM, etc.).

- getTimetable2017
  - params: [{
      type: "STUDENT" | "TEACHER" | ..., 
      id: <PERSON_OR_ENTITY_ID>,
      startDate: "YYYY-MM-DD",
      endDate: "YYYY-MM-DD",
      masterDataTimestamp: <epoch_ms or 0>,
      timetableTimestamp: 0,
      timetableTimestamps: [0, ...],
      auth: { user, otp, clientTime }
    }]
  - Returns periods for the date range:
    - periods[].startDateTime / endDateTime: ISO 8601, UTC ("Z")
    - periods[].elements: array of { type: CLASS|TEACHER|SUBJECT|ROOM, id, orgId }
    - periods[].text: lesson, substitution, info
    - periods[].can / periods[].is: capability/status flags
    - color fields: foreColor, backColor, innerForeColor, innerBackColor

- getAuthToken
  - params: [{ auth: { user, otp, clientTime } }]
  - Returns result.token (JWT).

## REST endpoints (require Bearer token)

- GET /WebUntis/api/rest/view/v3/mobile/data
  - Returns schoolYear, tenant info, and user summary
  - Useful to discover user.person.id (student ID) for timetable calls

- GET /WebUntis/api/rest/view/v1/dashboard/cards/status
  - Returns { unreadCardsCount: number }

- GET /WebUntis/api/rest/view/v1/trigger/startup
  - Returns { startupActions: [] }

## Push registration (requires Bearer token)

- POST https://push.webuntis.com/api/register
  - Headers: Authorization: Bearer <JWT>, Content-Type: application/json
  - Body:
    {
      "environment": "production",
      "product": "um",
      "deviceOs": "IOS" | "ANDROID",
      "fcmToken": "<FCM_TOKEN>",
      "deviceId": "<DEVICE_ID>"
    }

## Example cURL (redacted)

Replace placeholder values: <TENANT_ID>, <SCHOOL_B64>, <USERNAME>, <OTP>, <EPOCH_MS>, <JWT>, <PERSON_ID>, <JSESSIONID>.

1) getUserData2017 (bootstrap session)
```bash
curl -i 'https://{{baseHost}}/WebUntis/jsonrpc_intern.do?a=0&m=getUserData2017&s={{baseHost}}&school={{schoolLogin}}&v=i4.1.0' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: Tenant-Id="<TENANT_ID>"; schoolname="<SCHOOL_B64>"' \
  -d '{
    "jsonrpc": "2.0",
    "id": "UntisMobileiOS",
    "method": "getUserData2017",
    "params": [{
      "auth": { "user": "<USERNAME>", "otp": <OTP>, "clientTime": <EPOCH_MS> }
    }]
  }'
```

2) getAuthToken
```bash
curl -s 'https://{{baseHost}}/WebUntis/jsonrpc_intern.do?a=0&m=getAuthToken&s={{baseHost}}&school={{schoolLogin}}&v=i4.1.0' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: Tenant-Id="<TENANT_ID>"; schoolname="<SCHOOL_B64>"; JSESSIONID=<JSESSIONID>' \
  -d '{
    "jsonrpc": "2.0",
    "id": "UntisMobileiOS",
    "method": "getAuthToken",
    "params": [{
      "auth": { "user": "<USERNAME>", "otp": <OTP>, "clientTime": <EPOCH_MS> }
    }]
  }'
```

3) REST: mobile data
```bash
curl -s 'https://{{baseHost}}/WebUntis/api/rest/view/v3/mobile/data' \
  -H 'Authorization: Bearer <JWT>' \
  -H 'Cookie: Tenant-Id="<TENANT_ID>"; schoolname="<SCHOOL_B64>"; JSESSIONID=<JSESSIONID>'
```

4) JSON-RPC: getTimetable2017
```bash
curl -s 'https://{{baseHost}}/WebUntis/jsonrpc_intern.do?a=0&m=getTimetable2017&s={{baseHost}}&school={{schoolLogin}}&v=i4.1.0' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: Tenant-Id="<TENANT_ID>"; schoolname="<SCHOOL_B64>"; JSESSIONID=<JSESSIONID>' \
  -d '{
    "jsonrpc": "2.0",
    "id": "UntisMobileiOS",
    "method": "getTimetable2017",
    "params": [{
      "type": "STUDENT",
      "id": <PERSON_ID>,
      "startDate": "2025-08-11",
      "endDate": "2025-08-16",
      "masterDataTimestamp": 0,
      "timetableTimestamp": 0,
      "timetableTimestamps": [0,0,0,0,0,0],
      "auth": { "user": "<USERNAME>", "otp": <OTP>, "clientTime": <EPOCH_MS> }
    }]
  }'
```

## Data and formatting notes

- Dates in requests: "YYYY-MM-DD"
- Times in responses: ISO 8601 with Z (UTC)
- masterDataTimestamp/timetableTimestamp: 0 returns full payload; timestamps can be used for delta updates
- JWT: RS256; contains claims like tenant_id, sub (username), roles (e.g., STUDENT), locale, issuer "webuntis"

## Troubleshooting

- 401/403 on REST: Ensure you called getAuthToken and pass Authorization: Bearer <JWT>.
- 400/invalid auth: Check OTP freshness and ensure clientTime is current epoch ms.
- Missing data: Use /api/rest/view/v3/mobile/data to confirm your personId before timetable calls.