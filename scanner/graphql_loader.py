"""GraphQL schema discovery via the standard introspection query.

This is deliberately minimal - it exists to answer two questions:
1. Is introspection enabled (should usually be disabled in production)?
2. What queries/mutations does the schema expose, so sensitive-sounding
   ones (delete/admin/impersonate/...) can be flagged for manual review?
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
      fields { name }
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
