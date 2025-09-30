#!/usr/bin/env python3
"""
Take MISP JSON files and emit a compact version that keeps ONLY:

Event-level:
  - date, info, publish_timestamp, threat_level_id, timestamp, published

Event.Tag[]:
  - { name }

Event.Attribute[]:
  - { category, comment, timestamp, type, value, (to_ids optional) }
  - Hash-like types (md5/sha*/ssdeep/tlsh/etc.) => the ENTIRE value is replaced
    with a placeholder like "<sha256>" (or "<hash>" if type is unknown).
    We do NOT search for or mask substrings inside composite values; if the type
    contains any hash token (including "filename|md5"), the whole value is masked.

Event.Object[]:
  - { comment, description, meta-category, name, timestamp,
      Attribute: [{ category, comment, timestamp, type, value, (to_ids optional) }] }
  - Same masking rule for hash-like attribute types; long values truncated.

Other keys are dropped.

"""

from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

# --- Constants / Keep-lists ---

KEEP_EVENT_KEYS = {
    "date",
    "info",
    "publish_timestamp",   # canonical name
    "threat_level_id",
    "timestamp",
    "published",
}

# KEEP_ATTR_KEYS is built dynamically based on --drop-to-ids
BASE_ATTR_KEYS = ["category", "comment", "timestamp", "type", "value"]
TO_IDS_KEY = "to_ids"

KEEP_OBJ_KEYS  = ["comment", "description", "meta-category", "name", "timestamp"]

# Hash-like MISP attribute types to mask
HASH_TYPES = {
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
    "sha3", "sha3-224", "sha3-256", "sha3-384", "sha3-512",
    "imphash", "authentihash", "pehash", "vhash", "cdhash",
    "ssdeep", "tlsh",
}

LABEL_MAP_NUM2STR = {"1": "High", "2": "Medium", "3": "Low"}  # (not emitted, used only if you later choose)

# Heuristics to catch huge strings we should truncate (for non-hash types)
_RE_HEX_LONG = re.compile(r"^[0-9A-Fa-f]{40,}$")
_RE_B64ISH   = re.compile(r"^[A-Za-z0-9+/=\s]{80,}$")  # crude but useful


# --- Utils ---

def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _as_list(x) -> List[Any]:
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]

def _coerce_threat_level_id(x: Any) -> Optional[str]:
    if x is None:
        return None
    s = str(x).strip()
    return s  # keep "1"/"2"/"3" as strings; pass-through other values too

def _ensure_comment(d: Dict[str, Any]) -> None:
    if "comment" not in d:
        d["comment"] = ""

def _type_is_hashlike(attr_type: Optional[str]) -> bool:
    if not attr_type:
        return False
    t = attr_type.lower()
    return any(tok.strip() in HASH_TYPES for tok in t.split("|"))

def _first_hash_token(attr_type: Optional[str]) -> Optional[str]:
    if not attr_type:
        return None
    for tok in attr_type.lower().split("|"):
        tok = tok.strip()
        if tok in HASH_TYPES:
            return tok
    return None

def _looks_like_big_blob(val: str) -> bool:
    # very long hex or base64-ish, or just long string (for truncation only)
    if len(val) >= 256:
        return True
    if len(val) >= 40 and _RE_HEX_LONG.match(val):
        return True
    if len(val) >= 80 and _RE_B64ISH.match(val):
        return True
    return False

def _truncate(val: str, limit: int) -> str:
    if limit <= 0 or len(val) <= limit:
        return val
    return val[:limit] + "…"


# --- Core normalization for attribute values ---

def normalize_value(attr_type: str, value: Any, truncate_long: int) -> Any:
    """
    Normalize an Attribute.value:
      - If type is hash-like => mask ENTIRE value to "<{hash-type}>" (or "<hash>").
      - Else if very long string/blob => truncate to truncate_long
      - Else return as-is
    We do NOT search for hash substrings inside values; the decision is by type only.
    """
    if value is None or not isinstance(value, str):
        return value

    if _type_is_hashlike(attr_type):
        tok = _first_hash_token(attr_type)
        return f"<{tok}>" if tok else "<hash>"

    if _looks_like_big_blob(value) and truncate_long > 0:
        return _truncate(value, truncate_long)

    return value


# --- Strict simplifier ---

def simplify_event(evt_full: Dict[str, Any], keep_to_ids: bool, truncate_long: int) -> Optional[Dict[str, Any]]:
    """Return {"Event": out} simplified or None if not an event."""
    if "Event" not in evt_full or not isinstance(evt_full["Event"], dict):
        return None

    e = evt_full["Event"]

    # Normalize published_timestamp -> publish_timestamp
    if "publish_timestamp" not in e and "published_timestamp" in e:
        e["publish_timestamp"] = e["published_timestamp"]

    # Top-level Event
    out_e: Dict[str, Any] = {}
    for k in KEEP_EVENT_KEYS:
        if k in e:
            out_e[k] = e[k]

    # Coerce threat_level_id to string
    if "threat_level_id" in out_e:
        out_e["threat_level_id"] = _coerce_threat_level_id(out_e["threat_level_id"])

    # Tags: keep only {name}
    tags_in = _as_list(e.get("Tag"))
    tags_out: List[Dict[str, Any]] = []
    for t in tags_in:
        if isinstance(t, dict) and t.get("name"):
            tags_out.append({"name": t["name"]})
    if tags_out:
        out_e["Tag"] = tags_out

    # Build attr keep-list per CLI flag
    keep_attr_keys = BASE_ATTR_KEYS + ([TO_IDS_KEY] if keep_to_ids else [])

    # Attributes: keep only allowed keys; require type & value; ensure comment; mask/truncate value
    attrs_in = _as_list(e.get("Attribute"))
    attrs_out: List[Dict[str, Any]] = []
    for a in attrs_in:
        if not isinstance(a, dict):
            continue
        kept = {k: a.get(k) for k in keep_attr_keys if k in a}
        if kept.get("type") and kept.get("value") is not None:
            kept["value"] = normalize_value(kept.get("type", ""), kept["value"], truncate_long)
            _ensure_comment(kept)
            attrs_out.append(kept)
    if attrs_out:
        out_e["Attribute"] = attrs_out

    # Objects: keep allowed keys; ensure comment; filter inner attributes same way
    objs_in = _as_list(e.get("Object"))
    objs_out: List[Dict[str, Any]] = []
    for o in objs_in:
        if not isinstance(o, dict):
            continue
        so = {k: o.get(k) for k in KEEP_OBJ_KEYS if k in o}
        original_has_meta = bool(so)
        _ensure_comment(so)

        o_attrs_in = _as_list(o.get("Attribute"))
        o_attrs_out: List[Dict[str, Any]] = []
        for oa in o_attrs_in:
            if not isinstance(oa, dict):
                continue
            sa = {k: oa.get(k) for k in keep_attr_keys if k in oa}
            if sa.get("type") and sa.get("value") is not None:
                sa["value"] = normalize_value(sa.get("type", ""), sa["value"], truncate_long)
                _ensure_comment(sa)
                o_attrs_out.append(sa)

        if o_attrs_out:
            so["Attribute"] = o_attrs_out

        # Keep object only if it had any meta keys originally OR has kept attributes
        if original_has_meta or o_attrs_out:
            objs_out.append(so)

    if objs_out:
        out_e["Object"] = objs_out

    return {"Event": out_e}


# --- Manifest helpers ---

def read_manifest(path: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                # swallow malformed lines to be robust
                pass
    return rows

def normalize_label_field(r: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    """Returns (threat_level_id, threat_level_label). Not emitted in output JSON."""
    tl = r.get("threat_level_id") or r.get("threat_level")
    if tl is not None and str(tl) in {"1", "2", "3"}:
        tl_str = str(tl)
        return tl_str, LABEL_MAP_NUM2STR[tl_str]
    return None, None


# --- Driver that simplifies + writes dataset + new manifest ---

def simplify_and_write_dataset(
    input_dir: str,
    output_dir: str,
    manifest_rows: Dict[str, Dict[str, Any]],
    keep_to_ids: bool,
    truncate_long: int,
) -> None:
    ensure_dir(output_dir)
    new_manifest_path = os.path.join(output_dir, "manifest.jsonl")

    json_files = sorted([f for f in os.listdir(input_dir) if f.lower().endswith(".json")])

    with open(new_manifest_path, "w", encoding="utf-8") as manifest_out:
        for filename in json_files:
            in_path = os.path.join(input_dir, filename)
            try:
                # read raw as bytes so we can hash original
                with open(in_path, "rb") as f_in:
                    raw_bytes = f_in.read()

                # decode & load JSON
                raw_json = json.loads(raw_bytes.decode("utf-8", errors="replace"))

                # strict simplify
                simplified_json = simplify_event(raw_json, keep_to_ids=keep_to_ids, truncate_long=truncate_long)
                if not simplified_json:
                    print(f"[WARN] Skipping {filename}: no valid 'Event' to simplify.")
                    continue

                # write simplified
                out_path = os.path.join(output_dir, filename)
                out_bytes = json.dumps(
                    simplified_json, ensure_ascii=False, separators=(",", ":"), indent=4
                ).encode("utf-8")
                with open(out_path, "wb") as f_out:
                    f_out.write(out_bytes)

                # build new manifest record
                meta = manifest_rows.get(filename, {})
                tl_id, tl_lab = normalize_label_field(meta)  # NOTE: label not emitted below

                record: Dict[str, Any] = {
                    "filename": filename,
                    "sha256": sha256_bytes(out_bytes),
                    "source_sha256": sha256_bytes(raw_bytes),
                }
                # keep only numeric threat level id if present in original manifest (no label emitted)
                if tl_id is not None:
                    record["threat_level_id"] = tl_id

                # Pass through timestamps if they exist in the ORIGINAL manifest
                if "date" in meta:
                    record["date"] = meta["date"]
                if "publish_timestamp" in meta:
                    record["publish_timestamp"] = meta["publish_timestamp"]
                elif "published_timestamp" in meta:
                    record["publish_timestamp"] = meta["published_timestamp"]
                if "timestamp" in meta:
                    record["timestamp"] = meta["timestamp"]

                manifest_out.write(json.dumps(record, ensure_ascii=False) + "\n")

            except Exception as e:
                print(f"[ERR] Failed to process {filename}: {e}")


# --- CLI ---

def main():
    parser = argparse.ArgumentParser(
        description="Simplify a directory of MISP JSON events (strict keep-list) and write a new manifest.jsonl."
    )
    parser.add_argument(
        "--input-dir",
        default="/Users/murathanku/PycharmProjects/Cyber/snapshots_both/2025-08-20/raw",
        help="Directory containing raw MISP JSONs and the original manifest.jsonl"
    )
    parser.add_argument(
        "--output-dir",
        default="/Users/murathanku/PycharmProjects/Cyber/snapshots_both/2025-08-20/simplified2",
        help="Directory to save the simplified JSONs and the new manifest.jsonl"
    )
    parser.add_argument(
        "--truncate-long",
        type=int,
        default=512,
        help="Truncate very long string values to N characters (default: 512). Use 0 to disable."
    )
    parser.add_argument(
        "--drop-to-ids",
        action="store_true",
        help="If set, drop the 'to_ids' field from attributes. By default it is kept."
    )
    args = parser.parse_args()

    manifest_path = os.path.join(args.input_dir, "manifest.jsonl")
    if not os.path.exists(manifest_path):
        raise SystemExit(f"Error: manifest.jsonl not found in '{args.input_dir}'")

    # Read the original manifest to get metadata
    all_rows = read_manifest(manifest_path)
    manifest_lookup: Dict[str, Dict[str, Any]] = {row["filename"]: row for row in all_rows if "filename" in row}

    keep_to_ids = not args.drop_to_ids
    print(f"Simplifying JSONs from '{args.input_dir}' to '{args.output_dir}'...")
    print(f" - keep to_ids: {keep_to_ids}")
    print(f" - truncate-long: {args.truncate_long}")

    simplify_and_write_dataset(
        args.input_dir,
        args.output_dir,
        manifest_lookup,
        keep_to_ids=keep_to_ids,
        truncate_long=args.truncate_long,
    )

    print("\n[DONE] Simplification complete.")
    print(f"Simplified dataset is ready in: '{args.output_dir}'")

if __name__ == "__main__":
    main()
