"""Payload mutation engine for API fuzzing checks."""
from __future__ import annotations

import copy


UNICODE_EDGE_VALUES = ["\u202eadmin", "\u0000", "\ud83d\ude80", "\u200fuser"]
INTEGER_EDGE_VALUES = [0, -1, 2**31 - 1, 2**63 - 1, 999999999999999999999]


def generate_mutations(payload: dict) -> list[dict]:
    if not isinstance(payload, dict) or not payload:
        return []

    mutations = []

    # 1) Duplicate-ish keys using case variants to trigger parser confusion.
    dup = dict(payload)
    for k, v in list(payload.items())[:3]:
        dup[k.upper()] = v
    mutations.append(dup)

    # 2) Nested object growth.
    nested = copy.deepcopy(payload)
    nested["_meta"] = {"trace": {"a": {"b": {"c": "x"}}}}
    mutations.append(nested)

    # 3) Array expansion.
    arr = copy.deepcopy(payload)
    arr["items"] = [{"id": i, "v": "x"} for i in range(300)]
    mutations.append(arr)

    # 4) Unicode edge cases.
    uni = copy.deepcopy(payload)
    for i, (k, _) in enumerate(list(payload.items())[:2]):
        uni[k] = UNICODE_EDGE_VALUES[i % len(UNICODE_EDGE_VALUES)]
    mutations.append(uni)

    # 5) Integer boundary values.
    ints = copy.deepcopy(payload)
    for i, (k, v) in enumerate(list(payload.items())[:3]):
        if isinstance(v, int):
            ints[k] = INTEGER_EDGE_VALUES[i % len(INTEGER_EDGE_VALUES)]
    mutations.append(ints)

    # 6) Content confusion marker inside JSON body.
    ctype = copy.deepcopy(payload)
    ctype["_content_type_confusion"] = "text/xml"
    mutations.append(ctype)

    return mutations
