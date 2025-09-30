#!/usr/bin/env python3
# common.py — clean re-implementation from scratch
from __future__ import annotations

import hashlib
import os
import textwrap
from typing import Any, Dict, List, Optional

# --------------------------- Constants & small utils ---------------------------

THREAT_MAP = {
    "1": "High", "2": "Medium", "3": "Low", "4": "Undefined",
      1: "High",   2: "Medium",   3: "Low",   4: "Undefined",
}

def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def sha256_bytes(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()

def safe_int(x: Any) -> Optional[int]:
    if x is None:
        return None
    try:
        return int(x)
    except Exception:
        return None

def get_first(d: Dict[str, Any], *keys: str) -> Any:
    for k in keys:
        if isinstance(d, dict) and k in d:
            return d[k]
    return None

def _copy_if_present(src: Dict[str, Any], keys: List[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k in keys:
        if k in src:
            out[k] = src[k]
    return out

def _strip_tag(tag: Dict[str, Any]) -> Dict[str, Any]:
    # Keep at least the name; include local/relationship_type if present.
    out: Dict[str, Any] = {}
    for k in ("name", "local", "relationship_type"):
        if k in tag:
            out[k] = tag[k]
    if not out and "name" in tag:
        out["name"] = tag["name"]
    return out

def _is_empty(v: Any) -> bool:
    return v is None or v == "" or v == [] or v == {}

def clean_json_recursively(x: Any) -> Any:
    """Remove empty values recursively without altering types/keys."""
    if isinstance(x, dict):
        return {k: clean_json_recursively(v) for k, v in x.items() if not _is_empty(clean_json_recursively(v))}
    if isinstance(x, list):
        return [clean_json_recursively(v) for v in x if not _is_empty(clean_json_recursively(v))]
    return x

def scrub_labels(event_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Remove all threat_level keys to avoid leakage."""
    if not isinstance(event_dict, dict):
        return event_dict
    def _scrub(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: _scrub(v) for k, v in obj.items() if k not in ("threat_level", "threat_level_id")}
        if isinstance(obj, list):
            return [_scrub(v) for v in obj]
        return obj
    return _scrub(event_dict)

# --------------------------- Schema-faithful simplify --------------------------

def _simplify_attribute(attr: Dict[str, Any]) -> Dict[str, Any]:
    """Preserve important analyst signals; do not drop to_ids/uuid/object_relation/Tag."""
    keep = [
        "category","type","value","comment","timestamp","uuid","to_ids",
        "deleted","disable_correlation","first_seen","last_seen","object_relation",
    ]
    base = _copy_if_present(attr, keep)
    if isinstance(attr.get("Tag"), list):
        base["Tag"] = [_strip_tag(t) for t in attr["Tag"] if isinstance(t, dict)]
    return base

def _simplify_object(obj: Dict[str, Any]) -> Dict[str, Any]:
    """Keep MISP keys as-is: 'meta-category' and 'Attribute' (singular)."""
    keep_obj = [
        "name","description","meta-category","timestamp","uuid","template_uuid",
        "template_version","deleted","comment",
    ]
    out = _copy_if_present(obj, keep_obj)
    # Allow tolerant input that used 'meta_category' and map back without losing data.
    if "meta-category" not in out and "meta_category" in obj:
        out["meta-category"] = obj["meta_category"]
    # Attributes (support either key; write as 'Attribute')
    attrs = obj.get("Attribute") or obj.get("Attributes") or []
    out["Attribute"] = [_simplify_attribute(a) for a in attrs if isinstance(a, dict)]
    # Object references
    if isinstance(obj.get("ObjectReference"), list):
        kept_refs: List[Dict[str, Any]] = []
        for r in obj["ObjectReference"]:
            if not isinstance(r, dict):
                continue
            kept_refs.append({
                k: r.get(k) for k in (
                    "relationship_type","relationship","referenced_uuid","referenced_id",
                    "uuid","comment","timestamp","object_uuid"
                ) if k in r
            })
        if kept_refs:
            out["ObjectReference"] = kept_refs
    return out

def make_simplified_event(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Produce a 'simplified' event that is still schema-faithful and loss-aware.
    IMPORTANT: We DO NOT create or map a 'published_timestamp'. We keep 'publish_timestamp' only if present.
    """
    if "Event" not in raw:
        return None
    E = raw["Event"] or {}

    out_event: Dict[str, Any] = {}

    # Pass through commonly used top-level keys verbatim (no renaming)
    passthrough = [
        "date","info","analysis","published","publish_timestamp","timestamp",
        "uuid","extends_uuid","threat_level_id","Orgc","Org","distribution",
        "Galaxy","AttributeCount"
    ]
    out_event.update(_copy_if_present(E, passthrough))

    # If non-standard 'threat_level' exists (some feeds), keep alongside threat_level_id.
    if "threat_level" in E and "threat_level_id" not in out_event:
        out_event["threat_level"] = E["threat_level"]

    # Event-level tags
    if isinstance(E.get("Tag"), list):
        out_event["Tag"] = [_strip_tag(t) for t in E["Tag"] if isinstance(t, dict)]

    # Attributes
    if isinstance(E.get("Attribute"), list):
        out_event["Attribute"] = [_simplify_attribute(a) for a in E["Attribute"] if isinstance(a, dict)]

    # Objects
    if isinstance(E.get("Object"), list):
        out_event["Object"] = [_simplify_object(o) for o in E["Object"] if isinstance(o, dict)]

    return {"Event": out_event}

# ------------------------------- Textifier ------------------------------------

def _wrap_keep_urls(s: str, width: int, indent: int = 0) -> str:
    """
    Wrap text without inserting breaks inside URL tokens and preserving leading spaces/bullets.
    """
    if not s:
        return ""
    # Preserve initial indentation/prefix (e.g., "  • ")
    leading_ws = len(s) - len(s.lstrip(" "))
    prefix = s[:leading_ws]
    body = s[leading_ws:]
    tokens = body.split()
    if not tokens:
        return s

    lines: List[str] = []
    cur = prefix + tokens[0]
    for tok in tokens[1:]:
        # do not break URLs; treat token with :// as unbreakable (normal fit logic handles it)
        proposed = cur + " " + tok
        if len(proposed) <= width:
            cur = proposed
        else:
            lines.append(cur)
            cur = prefix + (" " * indent) + tok if indent else prefix + tok
    lines.append(cur)
    return "\n".join(lines)

def textify_event(event_dict: Dict, w=88) -> str:
    """Creates a human-readable text summary of a MISP event without UUIDs."""
    E = event_dict.get("Event", {})
    parts = []

    if E.get("date"):
        parts.append(f"Date: {E.get('date')}")
    if E.get("info"):
        parts.append(f"Info: {E.get('info')}")

    tags = [t.get("name") for t in E.get("Tag", []) if isinstance(t, dict) and t.get("name")]
    if tags:
        parts.append("Tags: " + ", ".join(tags))

    attributes = E.get("Attribute", [])
    if attributes:
        parts.append("Attributes:")
        for a in attributes:
            if not isinstance(a, dict):
                continue
            line = f"- [{a.get('category', '?')} / {a.get('type', '?')}] {a.get('value', '')}"
            if a.get("comment"):
                line += f" // {a.get('comment')}"
            line += f" (to_ids={a.get('to_ids', False)})"
            if a.get("Tag"):
                tnames = [t.get("name") for t in a.get("Tag", []) if t.get("name")]
                if tnames:
                    line += f"\n  • Tags: {', '.join(tnames)}"
            parts.append(line)

    objects = E.get("Object", [])
    if objects:
        parts.append("Objects:")
        for o in objects:
            if not isinstance(o, dict):
                continue
            parts.append(f"- {o.get('name', '?')} [{o.get('meta-category', '?')}] // {o.get('description', '')}")
            obj_attrs = o.get("Attribute", [])
            for oa in obj_attrs:
                if not isinstance(oa, dict):
                    continue
                line = f"  • [{oa.get('category', '?')} / {oa.get('type', '?')}] {oa.get('value', '')}"
                if oa.get("comment"):
                    line += f" // {oa.get('comment')}"
                line += f" (to_ids={oa.get('to_ids', False)})"
                parts.append(line)

            refs = o.get("ObjectReference", [])
            if refs:
                parts.append("    · References:")
                for r in refs:
                    parts.append(f"      - {r.get('relationship_type', '?')}")

    return "\n".join(parts)

# ----------------------------- Minimal manifest meta --------------------------

def parse_event_minimal(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Minimal per-event metadata for quick indexing in manifests.
    NOTE: We do NOT create or map 'published_timestamp'. We pass through 'publish_timestamp' only.
    """
    if "Event" not in raw:
        return {}
    e = raw["Event"] or {}
    threat = get_first(e, "threat_level_id", "threat_level")  # prefer standard id
    thr_str = None if threat is None else str(threat)
    return {
        "uuid": e.get("uuid"),
        "date": e.get("date"),
        "info": e.get("info"),
        "publish_timestamp": e.get("publish_timestamp"),
        "threat_level_id": thr_str if thr_str in {"1","2","3","4"} else None,
    }


def _strip_tag_names_only(tag_list):
    return [t.get("name") for t in (tag_list or []) if isinstance(t, dict) and t.get("name")]

def make_simplified_event_llm(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Aggressively simplified for LLM classification (keeps semantic signal, drops platform metadata).
    Keeps:
      - Event: date, info, Tag (names)
      - Attribute: category, type, value, comment, to_ids, Tag (names)
      - Object: name, description, meta-category, Attribute (same minimal fields), ObjectReference (relationship_type/relationship only)
    Drops:
      - All uuids, timestamps, published, analysis, Org/Orgc, deleted/disable_correlation, etc.
    """
    if "Event" not in raw:
        return None
    E = raw["Event"] or {}
    out: Dict[str, Any] = {
        "Event": {
            "date": E.get("date"),
            "info": E.get("info"),
            "Tag": [{"name": n} for n in _strip_tag_names_only(E.get("Tag"))],
            "Attribute": [],
            "Object": []
        }
    }
    # Attributes minimal
    for a in (E.get("Attribute") or []):
        if not isinstance(a, dict):
            continue
        out["Event"]["Attribute"].append({
            "category": a.get("category"),
            "type": a.get("type"),
            "value": a.get("value"),
            "comment": a.get("comment") or "",
            "to_ids": a.get("to_ids"),
            "Tag": [{"name": n} for n in _strip_tag_names_only(a.get("Tag"))] if a.get("Tag") else None
        })
        if out["Event"]["Attribute"][-1]["Tag"] is None:
            out["Event"]["Attribute"][-1].pop("Tag", None)

    # Objects minimal
    for o in (E.get("Object") or []):
        if not isinstance(o, dict):
            continue
        obj_out = {
            "name": o.get("name"),
            "description": o.get("description"),
            "meta-category": o.get("meta-category") or o.get("meta_category"),
            "Attribute": []
        }
        for oa in (o.get("Attribute") or o.get("Attributes") or []):
            if not isinstance(oa, dict):
                continue
            obj_out["Attribute"].append({
                "category": oa.get("category"),
                "type": oa.get("type"),
                "value": oa.get("value"),
                "comment": oa.get("comment") or "",
                "to_ids": oa.get("to_ids"),
                "object_relation": oa.get("object_relation"),
                "Tag": [{"name": n} for n in _strip_tag_names_only(oa.get("Tag"))] if oa.get("Tag") else None
            })
            if obj_out["Attribute"][-1]["Tag"] is None:
                obj_out["Attribute"][-1].pop("Tag", None)

        # Object references (relationship only; drop opaque UUIDs)
        refs = []
        for r in (o.get("ObjectReference") or []):
            if not isinstance(r, dict):
                continue
            rel = r.get("relationship_type") or r.get("relationship")
            if rel:
                refs.append({"relationship_type": rel})
        if refs:
            obj_out["ObjectReference"] = refs

        out["Event"]["Object"].append(obj_out)

    # Clean empties
    return clean_json_recursively(out)


def _simpl_attr_core(attr: Dict[str, Any]) -> Dict[str, Any]:
    """Core, LLM-focused attribute subset: category, type, value, comment, to_ids, + Tag names."""
    out: Dict[str, Any] = {
        "category": attr.get("category"),
        "type": attr.get("type"),
        "value": attr.get("value"),
    }
    if attr.get("comment"):
        out["comment"] = attr.get("comment")
    if "to_ids" in attr:
        out["to_ids"] = attr.get("to_ids")
    # Attribute-level tags (names only)
    if isinstance(attr.get("Tag"), list):
        names = [t.get("name") for t in attr["Tag"] if isinstance(t, dict) and t.get("name")]
        if names:
            out["Tag"] = [{"name": n} for n in names]
    return {k: v for k, v in out.items() if v not in (None, [], "")}

def _simpl_object_core(obj: Dict[str, Any]) -> Dict[str, Any]:
    """Core, LLM-focused object subset."""
    out: Dict[str, Any] = {
        "name": obj.get("name"),
        "description": obj.get("description"),
        "meta-category": obj.get("meta-category") or obj.get("meta_category"),
    }
    # Attributes (core fields only)
    attrs = obj.get("Attribute") or obj.get("Attributes") or []
    core_attrs = [_simpl_attr_core(a) for a in attrs if isinstance(a, dict)]
    if core_attrs:
        out["Attribute"] = core_attrs

    # Object references: include relationship_type, referenced_uuid, object_uuid, timestamp (as requested)
    refs = obj.get("ObjectReference") or []
    core_refs = []
    if isinstance(refs, list):
        for r in refs:
            if not isinstance(r, dict):
                continue
            keep = {}
            if r.get("relationship_type") is not None:
                keep["relationship_type"] = r.get("relationship_type")
            if r.get("referenced_uuid") is not None:
                keep["referenced_uuid"] = r.get("referenced_uuid")
            if r.get("object_uuid") is not None:
                keep["object_uuid"] = r.get("object_uuid")
            if r.get("timestamp") is not None:
                keep["timestamp"] = r.get("timestamp")
            if keep:
                core_refs.append(keep)
    if core_refs:
        out["ObjectReference"] = core_refs

    # Drop empties
    return {k: v for k, v in out.items() if v not in (None, [], "")}

def make_simplified_event(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Single, LLM-focused simplified view:
      - Keep: date, info, event-level Tag (names), Attribute core fields, Object core fields.
      - Drop: uuids (event/attr/object), published, analysis, Org/Orgc, publish_timestamp, numeric timestamps, deleted/disable_correlation.
      - Exception: keep ObjectReference {relationship_type, referenced_uuid, object_uuid, timestamp} to preserve graph context.
      - Never create 'published_timestamp' (we don't map it at all).
    """
    if "Event" not in raw:
        return None
    E = raw["Event"] or {}

    # Event core fields
    out_event: Dict[str, Any] = {}
    if E.get("date") is not None:
        out_event["date"] = E.get("date")
    if E.get("info") is not None:
        out_event["info"] = E.get("info")

    # Event-level tags (names only)
    tags = []
    for t in (E.get("Tag") or []):
        if isinstance(t, dict) and t.get("name"):
            tags.append({"name": t.get("name")})
    if tags:
        out_event["Tag"] = tags

    # Attributes (core)
    attrs = E.get("Attribute") or []
    core_attrs = [_simpl_attr_core(a) for a in attrs if isinstance(a, dict)]
    if core_attrs:
        out_event["Attribute"] = core_attrs

    # Objects (core)
    objs = E.get("Object") or []
    core_objs = [_simpl_object_core(o) for o in objs if isinstance(o, dict)]
    if core_objs:
        out_event["Object"] = core_objs

    return {"Event": out_event}

