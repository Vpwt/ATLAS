"""GraphQL schema discovery via the standard introspection query.

This is deliberately minimal - it exists to answer a few questions:
1. Is introspection enabled (should usually be disabled in production)?
2. What queries/mutations does the schema expose, so sensitive-sounding
   ones (delete/admin/impersonate/...) can be flagged for manual review?
3. Can the schema be used to build a deeply-nested query (depth/complexity
   DoS probe) or a request batching many aliased sub-queries (rate-limit
   bypass probe)? See `find_deep_query` / `build_alias_batch_query`.
"""
from typing import Optional

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        args { name }
        type {
          kind
          name
          ofType {
            kind
            name
            ofType { kind name ofType { kind name } }
          }
        }
      }
    }
  }
}
"""


def introspect(client, graphql_path: str) -> dict:
    """Sends a standard GraphQL introspection query. Returns the parsed JSON
    response, or {} if the request/response didn't work out (e.g. no GraphQL
    endpoint there, or introspection is disabled)."""
    try:
        resp = client.request("POST", graphql_path, json_body={"query": INTROSPECTION_QUERY},
                               auth_override="keep")
    except Exception:
        return {}
    try:
        return resp.json()
    except ValueError:
        return {}


def summarize_schema(introspection_result: dict) -> Optional[dict]:
    """Extracts query/mutation field names from an introspection response.
    Returns None if the response doesn't look like a valid introspection result."""
    schema = (introspection_result or {}).get("data", {}).get("__schema") if introspection_result else None
    if not schema:
        return None

    query_type_name = (schema.get("queryType") or {}).get("name")
    mutation_type_name = (schema.get("mutationType") or {}).get("name")

    queries, mutations = [], []
    for t in schema.get("types", []) or []:
        field_names = [f["name"] for f in (t.get("fields") or []) if f.get("name")]
        if t.get("name") == query_type_name:
            queries = field_names
        elif t.get("name") == mutation_type_name:
            mutations = field_names

    return {
        "queries": queries,
        "mutations": mutations,
        "type_count": len(schema.get("types", []) or []),
    }


def _build_types_index(schema: dict) -> dict:
    return {t["name"]: t for t in schema.get("types", []) or [] if t.get("name")}


def _unwrap_type(t: Optional[dict]) -> dict:
    """Unwrap NON_NULL/LIST wrappers (up to the depth fetched by
    INTROSPECTION_QUERY) to get the named underlying type."""
    while t and t.get("kind") in ("NON_NULL", "LIST") and t.get("ofType"):
        t = t["ofType"]
    return t or {}


def _build_nested_selection(types_by_name: dict, type_name: str, depth: int) -> Optional[str]:
    """Recursively builds a GraphQL selection set for `type_name`, preferring
    to keep nesting into object/interface-typed fields to build depth, and
    falling back to a scalar field once it can't nest further."""
    if depth <= 0:
        return None
    t = types_by_name.get(type_name)
    if not t:
        return None
    fields = t.get("fields") or []
    if not fields:
        return None

    scalar_field = None
    for f in fields:
        unwrapped = _unwrap_type(f.get("type"))
        if f.get("args"):
            continue  # skip fields that require arguments we don't have values for
        if scalar_field is None and unwrapped.get("kind") not in ("OBJECT", "INTERFACE"):
            scalar_field = f["name"]
        if unwrapped.get("kind") in ("OBJECT", "INTERFACE") and unwrapped.get("name") in types_by_name:
            nested = _build_nested_selection(types_by_name, unwrapped["name"], depth - 1)
            if nested:
                return "{ " + f["name"] + " " + nested + " }"

    if scalar_field:
        return "{ " + scalar_field + " }"
    return None


def find_deep_query(schema: dict, query_type_name: str, max_depth: int = 15) -> Optional[str]:
    """Best-effort: builds the deepest/most-nested query the schema allows,
    starting from a root query field, for a query-depth/complexity DoS
    probe. Returns None if the schema has no nestable object-typed fields
    (falls back gracefully - not every schema is vulnerable to this)."""
    types_by_name = _build_types_index(schema)
    query_type = types_by_name.get(query_type_name)
    if not query_type:
        return None

    for f in query_type.get("fields") or []:
        if f.get("args"):
            continue
        unwrapped = _unwrap_type(f.get("type"))
        if unwrapped.get("kind") in ("OBJECT", "INTERFACE") and unwrapped.get("name") in types_by_name:
            selection = _build_nested_selection(types_by_name, unwrapped["name"], max_depth)
            if selection:
                return "{ " + f["name"] + " " + selection + " }"
    return None


def build_alias_batch_query(schema: dict, query_type_name: str, batch_size: int = 50) -> Optional[str]:
    """Best-effort: builds a single query that repeats one no-argument root
    field under `batch_size` distinct aliases, for an alias-based
    rate-limit-bypass / batching-DoS probe. Returns None if no suitable
    (argument-free) root field is found."""
    types_by_name = _build_types_index(schema)
    query_type = types_by_name.get(query_type_name)
    if not query_type:
        return None

    candidate = next((f for f in (query_type.get("fields") or []) if not f.get("args")), None)
    if not candidate:
        return None

    unwrapped = _unwrap_type(candidate.get("type"))
    selection = ""
    if unwrapped.get("kind") in ("OBJECT", "INTERFACE") and unwrapped.get("name") in types_by_name:
        sub_fields = types_by_name[unwrapped["name"]].get("fields") or []
        leaf = next((f["name"] for f in sub_fields if not f.get("args")), None)
        selection = f" {{ {leaf} }}" if leaf else ""

    aliases = " ".join(f"a{i}: {candidate['name']}{selection}" for i in range(batch_size))
    return "{ " + aliases + " }"
