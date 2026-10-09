"""
Field-level mutation engine.

The visual editor lets a user drop a "Fuzz" block onto any field of any layer and
pick a strategy. This module takes the base block stack plus a list of fuzz rules
and produces N mutated block stacks. Those stacks are then built into packets by
builder.py.

Keeping mutation at the *field / block* level (rather than blindly flipping bytes
in a finished packet) is what makes it visual: every generated case can be shown
back to the user as a block stack with the changed field highlighted, so a learner
can see exactly what was varied and why.

Strategies
----------
  boundary   : min, max, +-1 around boundaries for the field's bit width
  random     : uniform random value within the field's range
  bitflip    : flip single bits in the current value
  wordlist   : cycle through a user-supplied list of values
  increment  : current value + step, repeated
  string_len : for string/bytes fields, vary the length (empty .. very long)
"""

from __future__ import annotations

import copy
import random


def _field_width_bits(proto_spec, field_name, default=32):
    for f in proto_spec.get("fields", []):
        if f["name"] == field_name:
            return f.get("bits", default)
    return default


def _boundary_values(bits):
    lo, hi = 0, (1 << bits) - 1
    cand = [lo, lo + 1, hi - 1, hi, hi // 2]
    # de-dup while preserving order
    seen, out = set(), []
    for c in cand:
        if 0 <= c <= hi and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _mutations_for_rule(rule, proto_spec, current_value, count):
    """Yield up to `count` mutated values for one fuzz rule."""
    strategy = rule.get("strategy", "random")
    bits = _field_width_bits(proto_spec, rule["field"])
    hi = (1 << bits) - 1

    if strategy == "boundary":
        vals = _boundary_values(bits)
        return vals[:count] if count else vals

    if strategy == "wordlist":
        words = rule.get("values", [])
        return words[:count] if count else words

    if strategy == "increment":
        step = int(rule.get("step", 1))
        try:
            base = int(current_value)
        except (TypeError, ValueError):
            base = 0
        return [(base + step * (i + 1)) & hi for i in range(max(count, 1))]

    if strategy == "bitflip":
        try:
            base = int(current_value)
        except (TypeError, ValueError):
            base = 0
        out = []
        for i in range(min(max(count, 1), bits)):
            out.append(base ^ (1 << i))
        return out

    if strategy == "string_len":
        lengths = [0, 1, 16, 255, 1024, 4096]
        fill = rule.get("fill", "A")
        lengths = lengths[:count] if count else lengths
        return [fill * n for n in lengths]

    # default: random
    return [random.randint(0, hi) for _ in range(max(count, 1))]


def fuzz(base_stack, rules, count=20, seed=None):
    """
    Produce mutated block stacks.

    rules: list of {"layer": <index>, "field": <name>, "strategy": ..., ...}
    Returns a list of {"stack": [...], "mutations": [{layer, field, value}]}.
    """
    from protocols.registry import all_protocols

    if seed is not None:
        random.seed(seed)

    catalogue = all_protocols()
    results = []

    # Pre-compute candidate value lists per rule.
    rule_values = []
    for rule in rules:
        layer_idx = int(rule["layer"])
        if layer_idx >= len(base_stack):
            continue
        proto = base_stack[layer_idx]["proto"]
        spec = catalogue.get(proto, {"fields": []})
        current = base_stack[layer_idx].get("fields", {}).get(rule["field"])
        values = _mutations_for_rule(rule, spec, current, count)
        if values:
            rule_values.append((rule, list(values)))

    if not rule_values:
        return results

    for i in range(count):
        mutated = copy.deepcopy(base_stack)
        applied = []
        for rule, values in rule_values:
            value = values[i % len(values)]
            layer_idx = int(rule["layer"])
            mutated[layer_idx].setdefault("fields", {})[rule["field"]] = value
            applied.append({"layer": layer_idx, "field": rule["field"], "value": value})
        results.append({"stack": mutated, "mutations": applied})

    return results
