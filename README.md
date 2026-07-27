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
| `bfla` | API5 Broken Function Level Authorization | Tests admin-like endpoints with no auth / a low-privilege token (explicit admin_only plus path/description heuristics); verb tampering supports safe mode (GET/HEAD/OPTIONS) or full mode |
| `injection` | API8 Security Misconfiguration | Sends SQLi/NoSQLi/command/SSTI/LDAP/XSS/deserialization-style payloads, watches for 5xx and leaked error signatures, runs boolean-differential probes, and adaptive time-based blind probes (2/4/6 second delays) |
| `ssrf` | API7 Server Side Request Forgery | Probes URL-shaped params/fields with cloud-metadata/loopback/file payloads; supports out-of-band callback confirmation with webhook.site or generic verify URL polling |
| `rate_limit` | API4 Unrestricted Resource Consumption | Bursts requests at an endpoint checking for HTTP 429; also tests uncapped pagination/page-size params |
| `headers` | API8 Security Misconfiguration | Checks for missing security headers (HSTS, CSP, X-Frame-Options) and overly permissive CORS |
| `http_methods` | API8 Security Misconfiguration | Checks for the HTTP TRACE method being enabled and dangerous methods advertised on unauthenticated paths |
| `mass_assignment` | API6 Unrestricted Access to Sensitive Business Flows | Sends extra fields like `is_admin`/`role` in write requests to see if they're silently accepted |
| `excessive_data_exposure` | API3 Broken Object Property Level Authorization | Scans GET responses for sensitive-looking fields (passwords, tokens, SSNs, etc.) that shouldn't be exposed |
| `jwt` | API2 Broken Authentication | Tests `alg=none` (and case-variant) forgery, `kid` header path traversal / key confusion, weak HMAC secrets (built-in plus optional external wordlist), and (given a public key via `jwt_public_key`/`jwks_url`) an RS256/ES256->HS256 algorithm-confusion attack |
| `error_disclosure` | API8 Security Misconfiguration | Sends malformed input, checks for leaked stack traces/internal paths |
| `api_inventory` | API9 Improper Inventory Management | Probes exposed docs/debug/admin paths and shadow versions; mines robots/sitemap and also scrapes homepage links/scripts for additional API-like paths |
| `graphql` | API9/API5/API4 Improper Inventory Management / Broken Function Level Authorization / Unrestricted Resource Consumption | Opt-in (`graphql_endpoint`): runs a standard introspection query, flags introspection being enabled, flags sensitive-sounding mutation names (delete/admin/grant/impersonate/...), probes for a query depth/complexity DoS vector, and probes for alias-based batching/rate-limit-bypass |
| `business_logic` | API6 Unrestricted Access to Sensitive Business Flows | Opt-in (`workflows`): replays configured flows, tests step-skipping and bounded step-reordering permutations; depth/combination limits are configurable |
| `unsafe_consumption` | API10 Unsafe Consumption of APIs | Heuristic checks for risky upstream-target handling by injecting internal/suspicious URLs into URL-like fields and looking for acceptance or leaked upstream failure details |

API10 is included as a heuristic black-box check (`unsafe_consumption`).
For strict assurance, pair it with internal architecture/testing data.

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
`graphql`, `business_logic`, `unsafe_consumption`.

## Config reference (key fields)

```yaml
base_url: "https://api.example.com"
auth_header: "Bearer YOUR_TEST_TOKEN"       # used as the "authenticated" identity
jwt_sample_token: ""                        # optional, enables JWT-specific checks
jwt_public_key: ""                          # optional PEM string, enables RS256->HS256 algorithm-confusion attack
jwks_url: ""                                # optional alt. to jwt_public_key: fetch the public key from a JWKS endpoint
jwt_secret_wordlist: ""                     # optional path to a newline-separated secret wordlist for HS* JWT testing
ssrf_callback_url: ""                       # optional attacker-controlled callback URL, enables out-of-band SSRF confirmation
ssrf_callback_verify_url: ""                # optional URL returning callback events text/JSON; include {probe} placeholder if needed
low_priv_auth_header: ""                    # optional 2nd, lower-privileged token, for BFLA testing
enable_verb_tampering: false                # backward-compatible switch (if true and mode=off, treated as full)
verb_tampering_mode: "safe"                 # off | safe | full
business_logic_max_skip_combo_size: 3       # increase for deeper skip-combination exploration
business_logic_max_reorder_steps: 5         # max steps in a workflow considered for reordering
business_logic_max_reorder_permutations: 30 # cap tested permutations per workflow
request_delay: 0.15                         # seconds between requests (be polite to your own API)
rate_limit_burst: 25                        # requests sent in the rate-limiting test

endpoints:
  - path: "/api/orders/{id}"
    method: GET
    auth_required: true
    id_param: "id"            # which param in `path`/`params` is the object ID
    sample_ids: ["1001"]       # IDs the test account legitimately owns
    foreign_ids: ["1002"]      # IDs belonging to someone else (should be forbidden)
    body_content_type: "application/json"  # optional: json, application/x-www-form-urlencoded, multipart/form-data, etc.
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
just individually. It also tries bounded step reordering permutations to
catch order-of-operations bugs (e.g. "complete" before "pay"). If the flow
still completes successfully without those checks/order constraints, that's a
**business logic bypass** and gets reported.

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
        ├── business_logic.py           # Multi-step workflow chaining / step-skip & reorder bypass detection
        └── unsafe_consumption.py       # API10 heuristic upstream-consumption safety checks
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

## Limitations 

- This is a black-box scanner by design. It cannot prove the absence of
  vulnerabilities; it can only detect observable signals and suspicious
  behaviors.
- Some checks rely on test data quality. BOLA is strongest when explicit
  owned vs foreign IDs are provided, though heuristic foreign-ID generation
  now runs when they are missing.
- Deep/exhaustive workflow exploration and GraphQL complexity analysis are
  configurable but intentionally bounded by default to keep scan runtime and
  request volume practical.
- Advanced exploit frameworks (full SQLi extraction, full gadget-chain
  generation, full JWT brute-force cracking) are outside scope of this
  scanner and are best handled by specialized tools.
- Browser-side JavaScript execution paths are partially covered through
  script scraping, but this is still not equivalent to a full authenticated
  dynamic browser crawler with user-journey replay.
