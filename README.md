# API Security Scanner

A lightweight Python scanner that probes a REST API for common issues aligned
with the [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/).
Built as a portfolio/learning project for testing APIs you own or are
explicitly authorized to test.

## ⚠️ Authorization required

This tool sends real, active-testing traffic to whatever `base_url` you
configure: unauthenticated requests, forged/garbage tokens, injection-style
payloads, SSRF probes, mass-assignment attempts, HTTP verb tampering, and
request bursts to check for missing rate limiting.

**Only run this against APIs you own or have explicit written authorization
to test.** Running these tests against third-party systems without
permission can violate laws like the U.S. Computer Fraud and Abuse Act (and
equivalents elsewhere) and most cloud providers' acceptable use policies.
The tool will ask you to type `YES` to confirm authorization before it sends
any requests (skip with `--yes` once you're comfortable).

## What it checks

Covers all 10 categories of the OWASP API Security Top 10 (2023), plus a few
extra checks that don't map to a single category:

| Check | OWASP API Top 10 (2023) | What it does |
|---|---|---|
| `auth` | API2 Broken Authentication | Tests protected endpoints with no token and with a garbage token |
| `bola` | API1 Broken Object Level Authorization | Swaps in "foreign" object IDs to see if they're wrongly accessible |
| `bfla` | API5 Broken Function Level Authorization | Tests `admin_only` endpoints with no auth / a low-privilege token; optionally tries undeclared HTTP methods per path (verb tampering) |
| `injection` | API8 Security Misconfiguration | Sends SQLi/NoSQLi/command/SSTI/LDAP/XSS-style payloads, watches for 5xx errors, leaked DB error signatures, or reflected unescaped HTML; also runs a time-based blind-injection probe (SLEEP/pg_sleep/WAITFOR/command-sleep payloads compared against a clean baseline) for cases with no visible error or reflection |
| `ssrf` | API7 Server Side Request Forgery | Probes URL-shaped params/fields (webhooks, callbacks, image URLs, etc.) with cloud-metadata/loopback/file:// payloads; optionally confirms true out-of-band SSRF via a configurable attacker-controlled callback URL (`ssrf_callback_url`) |
| `rate_limit` | API4 Unrestricted Resource Consumption | Bursts requests at an endpoint checking for HTTP 429; also tests uncapped pagination/page-size params |
| `headers` | API8 Security Misconfiguration | Checks for missing security headers (HSTS, CSP, X-Frame-Options) and overly permissive CORS |
| `http_methods` | API8 Security Misconfiguration | Checks for the HTTP TRACE method being enabled and dangerous methods advertised on unauthenticated paths |
| `mass_assignment` | API6 Unrestricted Access to Sensitive Business Flows | Sends extra fields like `is_admin`/`role` in write requests to see if they're silently accepted |
| `excessive_data_exposure` | API3 Broken Object Property Level Authorization | Scans GET responses for sensitive-looking fields (passwords, tokens, SSNs, etc.) that shouldn't be exposed |
| `jwt` | API2 Broken Authentication | Tests `alg=none` (and case-variant) forgery, `kid` header path traversal / key confusion, a small list of common weak HMAC secrets, and (given a public key via `jwt_public_key`/`jwks_url`) an RS256/ES256->HS256 algorithm-confusion attack |
| `error_disclosure` | API8 Security Misconfiguration | Sends malformed input, checks for leaked stack traces/internal paths |
| `api_inventory` | API9 Improper Inventory Management | Probes for exposed docs/debug/admin paths (`.env`, `.git`, actuator, swagger) and shadow/older API version prefixes; also passively mines `robots.txt`/`sitemap.xml` for undocumented paths |
| `graphql` | API9/API5/API4 Improper Inventory Management / Broken Function Level Authorization / Unrestricted Resource Consumption | Opt-in (`graphql_endpoint`): runs a standard introspection query, flags introspection being enabled, flags sensitive-sounding mutation names (delete/admin/grant/impersonate/...), probes for a query depth/complexity DoS vector, and probes for alias-based batching/rate-limit-bypass |
| `business_logic` | API6 Unrestricted Access to Sensitive Business Flows | Opt-in (`workflows`): replays a configured multi-step flow, then re-replays it with `required` steps removed (single steps, then combinations of 2-3) to detect step-skipping bypasses (e.g. completing an order without paying, or bypassing two checks only when skipped together) |

`API10:2023 Unsafe Consumption of APIs` isn't covered by an automated check
since it depends on knowing which third-party APIs *your* API calls
internally - see Limitations below.

Every finding also carries a `cvss_score` (derived from severity) and, where
a live HTTP request produced it, a ready-to-run `curl` **PoC/reproduction
command** - both shown in the console summary and in the HTML report.
## Setup

```bash
pip install -r requirements.txt
```

## Usage

1. Copy `example_config.yaml` to `config.yaml` and fill in your API's base
   URL, auth token, and the endpoints you want tested. See the comments in
   `example_config.yaml` for the full field reference (especially
   `id_param` / `sample_ids` / `foreign_ids`, which power the BOLA check,
   and `admin_only`, which powers the BFLA check).

   Instead of hand-listing every endpoint, you can set `openapi_spec` to a
   local OpenAPI 3.x/Swagger 2.0 file (or an http(s) URL) to auto-discover
   endpoints - see `example_openapi.yaml` for the format and the
   [OpenAPI spec discovery](#openapi-spec-discovery) section below. A Postman
   Collection v2.x export (`postman_collection`) works as an alternative
   discovery source too.

   Instead of pasting a static `auth_header`, you can set a `login:` block so
   the scanner logs in itself (and optionally refreshes the token
   periodically for long scans) - see [Automated login](#automated-login--token-refresh)
   below.

2. Run the scanner:

   ```bash
   python main.py --config config.yaml --output report.html
   ```

3. Confirm authorization when prompted, then review the generated
   `report.html` (or the console summary printed inline).

### Useful flags

```bash
# Run only specific checks
python main.py --config config.yaml --checks auth,bola,headers

# Skip the interactive authorization prompt (e.g. in CI)
python main.py --config config.yaml --yes

# Custom report path
python main.py --config config.yaml --output reports/scan_2026_07_27.html
```

Available check names: `auth`, `bola`, `bfla`, `injection`, `ssrf`,
`rate_limit`, `headers`, `http_methods`, `mass_assignment`,
`excessive_data_exposure`, `jwt`, `error_disclosure`, `api_inventory`,
`graphql`, `business_logic`.

## Config reference (key fields)

```yaml
base_url: "https://api.example.com"
auth_header: "Bearer YOUR_TEST_TOKEN"       # used as the "authenticated" identity
jwt_sample_token: ""                        # optional, enables JWT-specific checks
jwt_public_key: ""                          # optional PEM string, enables RS256->HS256 algorithm-confusion attack
jwks_url: ""                                # optional alt. to jwt_public_key: fetch the public key from a JWKS endpoint
ssrf_callback_url: ""                       # optional attacker-controlled callback URL, enables out-of-band SSRF confirmation
low_priv_auth_header: ""                    # optional 2nd, lower-privileged token, for BFLA testing
enable_verb_tampering: false                # opt-in: try undeclared HTTP methods per path (can hit DELETE/PUT)
request_delay: 0.15                         # seconds between requests (be polite to your own API)
rate_limit_burst: 25                        # requests sent in the rate-limiting test

endpoints:
  - path: "/api/orders/{id}"
    method: GET
    auth_required: true
    id_param: "id"            # which param in `path`/`params` is the object ID
    sample_ids: ["1001"]       # IDs the test account legitimately owns
    foreign_ids: ["1002"]      # IDs belonging to someone else (should be forbidden)
    params:
      id: "1001"

  - path: "/api/admin/users"
    method: GET
    auth_required: true
    admin_only: true           # should be rejected for unauthenticated/non-admin callers (BFLA)

# Optional, opt-in extras (see the fully-commented example_config.yaml):
# postman_collection: "my_collection.postman_collection.json"  # alt. to openapi_spec
# graphql_endpoint: "/graphql"                                  # enables the `graphql` check
# login: {url: "/api/login", method: POST, body: {...}, token_field: "access_token"}
# workflows: [{name: "checkout_flow", steps: [...]}]
```

## Automated login / token refresh

Instead of (or in addition to) `auth_header`, set a `login:` block and the
scanner will POST (or any method you choose) to a login endpoint first and
use the token it gets back for every subsequent request:

```yaml
login:
  url: "/api/login"
  method: POST
  body: {username: "testuser", password: "testpassword"}
  token_field: "access_token"    # dot-path into the JSON response, e.g. "data.token"
  header_prefix: "Bearer"
  refresh_interval: 0             # seconds; >0 re-logs-in periodically during long scans
```

If login fails, the scanner prints a warning and falls back to `auth_header`
if one is also configured.

## Business logic workflow chaining

`workflows:` lets you describe a multi-step flow (e.g. create an order, pay
for it, complete it). The scanner replays it end-to-end as a baseline, then
re-replays it with `required: true` steps removed - first one at a time,
then in combinations of 2 (and 3, if there are few enough required steps)
- to catch bypasses that only appear when steps are skipped *together*, not
just individually. If the flow still completes successfully without those
steps, that's a **business logic bypass** (e.g. an order can be completed
without payment) and gets reported as a CRITICAL finding.

```yaml
workflows:
  - name: "checkout_flow"
    steps:
      - name: "create_order"
        path: "/api/orders"
        method: POST
        body: {product_id: "123", qty: 1}
        extract: {order_id: "id"}   # pulls `id` from the response into {order_id}
      - name: "pay_order"
        path: "/api/orders/{order_id}/pay"
        method: POST
        body: {card: "4111111111111111"}
        required: true              # tries skipping this step (alone, and combined with others)
      - name: "complete_order"
        path: "/api/orders/{order_id}/complete"
        method: POST
```

## GraphQL support

Set `graphql_endpoint` (e.g. `/graphql`) to enable the `graphql` check. It's
opt-in and off by default so the scanner never probes a path that doesn't
exist. When set, it runs a standard introspection query and:

- flags a MEDIUM finding if introspection is enabled at all in what looks
  like a production target
- flags a HIGH finding if any discovered mutation name looks sensitive
  (`delete`, `remove`, `admin`, `role`, `permission`, `password`,
  `impersonate`, `grant`, `promote`)
- flags a HIGH finding if a deeply-nested query (built recursively from the
  discovered schema, up to depth 15) is accepted without any
  depth/complexity-limit error - a common resource-exhaustion DoS vector
- flags a MEDIUM finding if a single request containing 50 aliased copies of
  the same root field is accepted without error - aliasing is a well-known
  way to bypass per-request rate limiting

## JWT algorithm-confusion attack

If the sample token in `jwt_sample_token` uses an asymmetric algorithm
(RS256/RS384/RS512/ES256/ES384/ES512/PS256/...), provide the server's public
key via `jwt_public_key` (a PEM string) or `jwks_url` (a JWKS endpoint to
fetch it from) to additionally test for an RS256->HS256 algorithm-confusion
attack: the token is re-signed with `alg=HS256` using the public key's own
bytes as the HMAC secret. Some JWT libraries/hand-rolled verification code
load "the verification key" generically without pinning the expected
algorithm, and will accept this - letting anyone who knows the public key
(which is, by design, often actually public) forge arbitrary valid tokens.
This is flagged as CRITICAL if accepted.

```yaml
jwt_sample_token: "eyJhbGciOiJSUzI1NiIs..."
jwt_public_key: |
  -----BEGIN PUBLIC KEY-----
  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB...
  -----END PUBLIC KEY-----
# or, instead of pasting a PEM directly:
# jwks_url: "https://api.example.com/.well-known/jwks.json"
```

## Out-of-band SSRF confirmation

Some SSRF vulnerabilities give no visible signal in the HTTP response (the
server makes the outbound request, but nothing about it is reflected back).
Set `ssrf_callback_url` to an attacker-controlled listener URL you control
(e.g. a [webhook.site](https://webhook.site) URL, or another
interactsh/Burp Collaborator-style collector) and the `ssrf` check will send
a unique per-parameter token appended to that URL into every SSRF-prone
field. If the target actually makes the outbound call, your listener
records it - definitive proof of SSRF that response-based signals alone
can't provide.

```yaml
ssrf_callback_url: "https://webhook.site/11111111-2222-3333-4444-555555555555"
```

Automatic confirmation (polling for the hit and reporting a CRITICAL
finding) is currently only implemented for `webhook.site` URLs. For other
listeners, the scanner still sends the probes and prints an INFO finding
reminding you to check your dashboard manually for a hit containing a
`probe=` token.

## OpenAPI spec discovery

Set `openapi_spec` in `config.yaml` to a local file path or an `http(s)` URL
pointing at an OpenAPI 3.x / Swagger 2.0 document (JSON or YAML):

```yaml
openapi_spec: "example_openapi.yaml"
```

The scanner will parse every operation in `paths` into an `Endpoint`,
filling in:

- path/query parameter placeholder values from each parameter's `schema`
  (using `example`/`default`/`enum` when present, otherwise a type-based
  guess like `"test"`, `1`, or `true`); `allOf` subschemas are merged
  together and `oneOf`/`anyOf` uses the first alternative as a
  representative example
- request bodies from the operation's `requestBody` example/schema - the
  media-type entry is chosen preferring `application/json` (and `+json`
  suffixed types like `application/vnd.api+json`), then
  `application/x-www-form-urlencoded`/`multipart/form-data`, then whatever's
  listed first, so non-JSON-labeled bodies still get a best-effort example
  instead of being skipped
- `auth_required` from the operation's (or the document's global) `security`
  field - an empty `security: []` list means "no auth required"

What it *can't* infer from a spec: which IDs your test account owns vs. IDs
belonging to someone else. If `openapi_spec` is set, entries under
`endpoints:` are treated as overrides - matched to a discovered endpoint by
method + path - and merged on top of it, so you only need to specify the
fields you want to add or change (typically `id_param` / `sample_ids` /
`foreign_ids` for BOLA testing). An override whose path/method isn't found in
the spec is added as an extra endpoint. If `openapi_spec` is *not* set,
`endpoints:` is used as-is, exactly like before.

## Project structure

```
api_security_scanner/
├── main.py                    # CLI entry point
├── example_config.yaml        # Copy this to config.yaml and edit
├── example_openapi.yaml       # Sample OpenAPI spec for endpoint auto-discovery
├── requirements.txt
└── scanner/
    ├── models.py               # Endpoint / Finding data classes (+ CVSS scoring)
    ├── http_client.py          # requests wrapper (auth stripping, delays, curl PoC capture, token refresh hook)
    ├── config_loader.py        # YAML -> config/Endpoint objects
    ├── openapi_loader.py       # OpenAPI/Swagger spec -> Endpoint objects
    ├── postman_loader.py       # Postman Collection v2.x export -> Endpoint objects
    ├── graphql_loader.py       # GraphQL introspection query + schema summarization
    ├── auth_flow.py            # Automated login + periodic token refresh
    ├── report.py               # console + HTML report generation (CVSS/PoC columns, attack-surface table)
    └── checks/
        ├── auth.py                     # API2 Broken Authentication
        ├── bola.py                     # API1 Broken Object Level Authorization
        ├── bfla.py                     # API5 Broken Function Level Authorization
        ├── injection.py                # API8 SQLi/NoSQLi/command/SSTI/LDAP/XSS/deserialization smoke tests
        ├── ssrf.py                     # API7 Server Side Request Forgery
        ├── rate_limit.py               # API4 Unrestricted Resource Consumption
        ├── headers.py                  # API8 Security headers / CORS
        ├── http_methods.py             # API8 TRACE / verb misconfiguration
        ├── mass_assignment.py          # API6 Unrestricted Access to Sensitive Business Flows
        ├── excessive_data_exposure.py  # API3 Broken Object Property Level Authorization
        ├── jwt_checks.py               # API2 JWT forgery / weak secrets / kid injection
        ├── error_disclosure.py         # API8 Verbose error / stack trace leaks
        ├── api_inventory.py            # API9 Improper Inventory Management (+ robots.txt/sitemap.xml discovery)
        ├── graphql.py                  # GraphQL introspection / sensitive mutation discovery
        └── business_logic.py           # Multi-step workflow chaining / step-skip bypass detection
```

## Extending it

Each check is a standalone module with a `run(client, endpoints, ...) ->
list[Finding]` function, registered in `ALL_CHECKS` in `main.py`. To add a
new check:

1. Create `scanner/checks/your_check.py` with a `run()` function that
   returns a list of `Finding` objects (see `scanner/models.py`).
2. Import it in `main.py` and add it to `ALL_CHECKS`.

Ideas for extensions: GraphQL introspection abuse checks, OAuth scope
over-permission checks, or response-time-based user enumeration detection.

## Limitations (be honest about these in interviews!)

- The injection check is a *smoke test*, not a replacement for a dedicated
  fuzzer like `sqlmap` — it catches obvious cases (5xx errors, leaked
  stack traces, reflected payloads), plus a small time-based blind
  injection probe (SLEEP/pg_sleep/WAITFOR/command-sleep payloads compared
  against a clean baseline). The time-based probe only tries a handful of
  representative payloads/DBMSes and one fixed delay (4s) - it's a smoke
  test for blind injection, not a full blind-injection fuzzer.
- The SSRF check relies on leaked cloud-metadata/file content, a
  slow/timing anomaly, or (if `ssrf_callback_url` is configured) a true
  out-of-band callback hit. Automatic confirmation of the callback hit is
  currently only implemented for `webhook.site` URLs - other
  interactsh/Collaborator-style listeners require a manual dashboard check.
- OpenAPI spec discovery handles `allOf`/`oneOf`/`anyOf` schema composition
  and picks a best-effort content-type (preferring JSON, then
  form/multipart, then whatever's first) for request body examples, but it
  still doesn't handle every OpenAPI feature (e.g. OAuth2 flow details, or
  wire-format differences - request bodies are always sent as JSON
  regardless of the spec's declared content type, since the whole scanner
  is JSON-body-oriented).
- BOLA/mass-assignment checks still need you to manually specify
  sample/foreign IDs (via `endpoints:` overrides) since a spec has no concept
  of "an ID my test account owns" vs. "an ID belonging to someone else";
  BFLA similarly needs `admin_only` flags (and ideally a
  `low_priv_auth_header`) to be meaningful.
- Verb tampering (part of `bfla`) is opt-in (`enable_verb_tampering`)
  because it can exercise destructive HTTP verbs (DELETE/PUT/PATCH) against
  real endpoints - only enable it against a test/staging environment.
- JWT checks cover `alg=none` (+ case variants), a `kid`-header path
  traversal probe, a short common-secret wordlist, and (given
  `jwt_public_key`/`jwks_url`) an RS256/ES256→HS256 algorithm-confusion
  attack — still not a full JWT cracker, and the confusion attack needs the
  server's public key supplied/discoverable up front.
- `API10:2023 Unsafe Consumption of APIs` has no automated check - it
  requires knowing which third-party/upstream APIs your service calls,
  which isn't discoverable from the outside.
- There's no JavaScript-rendering crawler - "attack surface discovery" beyond
  OpenAPI/Postman/manual config is limited to passively parsing
  `robots.txt`/`sitemap.xml` (`api_inventory` check). Anything only
  reachable by executing client-side JS won't be found.
- The HTML report's "attack surface" section is a text table of endpoints
  tested, not a visual/graphical map.
- `business_logic` step-skip detection tries removing `required` steps
  individually and in combinations of up to 2 (or 3, if there are 6 or
  fewer required steps, to bound request count) - it doesn't try
  reordering steps.
- Deserialization checks (`injection`) only send a couple of generic
  PHP/Java gadget *markers* and look for related error signatures - this is
  a smoke test, not a real gadget-chain fuzzer (e.g. `ysoserial`).
- `graphql` support includes introspection, a query-depth/complexity DoS
  probe, and an alias-based batching probe, but both probes are best-effort
  (built from whatever the discovered schema allows to nest/repeat) and
  don't attempt full cost-based complexity analysis like a real GraphQL
  security scanner would.
