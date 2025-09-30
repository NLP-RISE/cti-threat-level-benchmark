#!/usr/bin/env python3

import os
import json
import argparse
import shutil
import random
from typing import Dict, Any, List, Optional, Tuple
from transformers import AutoTokenizer, logging
from tqdm import tqdm

# Suppress verbose logging from the transformers library
logging.set_verbosity_error()

LABEL_MAP_NUM2STR = {"1": "High", "2": "Medium", "3": "Low"}
LABEL_TEXT2ID = {
    "1": "1", "high": "1",
    "2": "2", "medium": "2",
    "3": "3", "low": "3",
}

# ---------------------------
# Threshold / tokenizer utils
# ---------------------------

def calculate_safe_threshold(max_context_length: int, overhead_config: dict) -> int:
    prompt_overhead = overhead_config.get('prompt_overhead', 400)
    output_buffer = overhead_config.get('output_buffer', 120)
    variance_percentage = overhead_config.get('variance_percentage', 0.10)  # 10% buffer

    available_tokens = max_context_length - prompt_overhead - output_buffer
    variance_buffer = int(available_tokens * variance_percentage)
    safe_threshold = available_tokens - variance_buffer

    print(f"Max Context Length: {max_context_length}")
    print(f"(-) Prompt & Output Overhead: {prompt_overhead + output_buffer}")
    print(f"(-) Tokenizer Variance Buffer ({int(variance_percentage*100)}%): {variance_buffer}")
    print(f"(=) Safe Data Token Threshold: {safe_threshold}\n")

    if safe_threshold <= 0:
        raise ValueError("Calculated safe threshold is zero or negative. "
                         "Check your max_context_length and overhead values.")
    return safe_threshold

# ---------------------------
# Label helpers
# ---------------------------

def read_manifest_labels(manifest_path: str) -> Dict[str, Dict[str, Any]]:
    """Read labels/meta from a manifest.jsonl if present. Returns filename->row."""
    idx: Dict[str, Dict[str, Any]] = {}
    if not os.path.exists(manifest_path):
        return idx
    with open(manifest_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                fn = r.get("filename")
                if fn:
                    idx[fn] = r
            except Exception:
                pass
    return idx

def normalize_label_value(val: Any) -> Optional[Tuple[str, str]]:
    """
    Normalize various label forms to ('1'|'2'|'3', 'High'|'Medium'|'Low').
    Returns None if not a valid label.
    """
    if val is None:
        return None
    s = str(val).strip()
    if not s:
        return None
    lid = LABEL_TEXT2ID.get(s.lower())
    if lid in ("1", "2", "3"):
        return lid, LABEL_MAP_NUM2STR[lid]
    # Maybe the string is exactly 'High'/'Medium'/'Low' with case
    ss = s.lower()
    if ss in ("high", "medium", "low"):
        lid = LABEL_TEXT2ID[ss]
        return lid, LABEL_MAP_NUM2STR[lid]
    return None

def get_label_for_file(fname: str, idx: Dict[str, Dict[str, Any]], json_obj: Optional[Dict[str, Any]]) -> Optional[Tuple[str, str]]:
    """
    Prefer manifest label; else read from JSON Event fields.
    """
    if fname in idx:
        r = idx[fname]
        # common fields in your pipeline
        for key in ("threat_level_id", "threat_level", "threat_level_label"):
            if key in r:
                res = normalize_label_value(r[key])
                if res:
                    return res
    if json_obj is not None:
        Ev = json_obj.get("Event") if isinstance(json_obj, dict) else None
        if isinstance(Ev, dict):
            for key in ("threat_level_id", "threat_level"):
                if key in Ev:
                    res = normalize_label_value(Ev[key])
                    if res:
                        return res
    return None

def stratified_split(file_label_pairs, test_size: float, seed: int):
    """
    Stratified split by label id ('1','2','3').
    Returns (train_pairs, test_pairs), where each item is (filename, label_id).
    """
    by_label = {}
    for fn, lid in file_label_pairs:
        by_label.setdefault(lid, []).append((fn, lid))

    rng = random.Random(seed)
    train, test = [], []

    for lid, group in by_label.items():
        group_sorted = sorted(group)  # stable base order
        rng.shuffle(group_sorted)
        n = len(group_sorted)
        k = max(1, int(round(n * test_size))) if n > 0 else 0
        test.extend(group_sorted[:k])
        train.extend(group_sorted[k:])

    return train, test

def print_label_stats(title: str, file_label_pairs: List[Tuple[str, str]]) -> None:
    total = len(file_label_pairs)
    by_label: Dict[str, int] = {"1": 0, "2": 0, "3": 0}
    for _, lid in file_label_pairs:
        if lid in by_label:
            by_label[lid] += 1
    print(f"\n[{title}] (n={total})")
    for lid in ("1", "2", "3"):
        cnt = by_label[lid]
        pct = (100.0 * cnt / total) if total else 0.0
        print(f"  {lid} ({LABEL_MAP_NUM2STR[lid]:6}): {cnt:5}  ({pct:5.1f}%)")

def write_manifest(path: str, file_label_pairs: List[Tuple[str, str]]) -> None:
    rows = []
    for fn, lid in file_label_pairs:
        rows.append({
            "filename": fn,
            "threat_level_id": lid,
            "threat_level_label": LABEL_MAP_NUM2STR[lid],
        })
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

# ---------------------------
# Markdown rendering helpers
# ---------------------------

def _event_core_fields(Ev: Dict[str, Any]) -> Tuple[str, Optional[str], Optional[str]]:
    date = str(Ev.get("date", "")).strip()
    info = str(Ev.get("info", "")).strip()
    tl_raw = Ev.get("threat_level_id") or Ev.get("threat_level")
    tl_norm = normalize_label_value(tl_raw)
    tl_str = None
    if tl_norm:
        lid, lname = tl_norm
        tl_str = f"{lid} ({lname})"
    return f"{date}: {info}" if date or info else info or date or "Threat Report", date if date else None, tl_str

def _tags_line(tags: List[Dict[str, Any]]) -> Optional[str]:
    names = []
    for t in tags or []:
        n = t.get("name")
        if n:
            names.append(str(n))
    return ", ".join(names) if names else None

def _group_by_category(attrs: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    for a in attrs or []:
        if not isinstance(a, dict):
            continue
        cat = a.get("category") or "Uncategorized"
        out.setdefault(cat, []).append(a)
    return out

def _fmt_comment_suffix(comment: Optional[str]) -> str:
    if comment:
        c = str(comment).strip()
        if c:
            return f" — {c}"
    return ""

def render_markdown_for_event(event_json: Dict[str, Any]) -> str:
    Ev = event_json.get("Event", {})
    title, date, tl = _event_core_fields(Ev)

    # H1
    lines: List[str] = [f"# Threat Report: {title}", "", ""]

    # Key Intelligence
    lines.append("## Key Intelligence")
    if date:
        lines.append(f"* Date: {date}")
    if tl:
        lines.append(f"* Threat Level: {tl}")

    tags_line = _tags_line(Ev.get("Tag", []))
    if tags_line:
        lines.append(f"* Tags: {tags_line}")
    lines.extend(["", "---", ""])

    # Top-level Attributes -> IOCs (grouped by category)
    top_attrs = Ev.get("Attribute", [])
    if isinstance(top_attrs, list) and top_attrs:
        lines.append("## Indicators of Compromise (IOCs)")
        grouped = _group_by_category(top_attrs)
        for cat in sorted(grouped.keys()):
            lines.append(f"### {cat}")
            for a in grouped[cat]:
                atype = a.get("type", "unknown")
                aval = a.get("value", "")
                comment = _fmt_comment_suffix(a.get("comment"))
                lines.append(f"* {atype}: {aval}{comment}")
            lines.append("")  # spacer
    else:
        # If no top-level attributes, still maintain structure
        lines.append("## Indicators of Compromise (IOCs)")
        lines.append("_No top-level indicators._")
        lines.append("")

    # Objects
    objs = Ev.get("Object", [])
    if isinstance(objs, list) and objs:
        lines.append("## Objects")
        for o in objs:
            if not isinstance(o, dict):
                continue
            name = (o.get("name") or "").strip()
            desc = (o.get("description") or "").strip()
            header = name if name else "object"
            if desc:
                header = f"{header} — {desc}"
            lines.append(f"### {header}")

            oattrs = o.get("Attribute", [])
            if isinstance(oattrs, list) and oattrs:
                for oa in oattrs:
                    if not isinstance(oa, dict):
                        continue
                    cat = oa.get("category") or "Uncategorized"
                    atype = oa.get("type", "unknown")
                    aval = oa.get("value", "")
                    comment = _fmt_comment_suffix(oa.get("comment"))
                    # Include CATEGORY explicitly in each bullet (fixes missing 'External analysis')
                    lines.append(f"* [{cat}] {atype}: {aval}{comment}")
            else:
                lines.append("* _No attributes_")
            lines.append("")  # spacer

    md = "\n".join(lines).rstrip() + "\n"
    return md

# ---------------------------
# Main filtering + outputs
# ---------------------------

def ensure_clean_dir(path: str) -> None:
    if os.path.exists(path):
        shutil.rmtree(path)
    os.makedirs(path, exist_ok=True)

def copy_kept_jsons(src_dir: str, dst_dir: str, kept_filenames: List[str]) -> None:
    os.makedirs(dst_dir, exist_ok=True)
    for fn in kept_filenames:
        shutil.copy(os.path.join(src_dir, fn), os.path.join(dst_dir, fn))

def write_markdowns(src_dir: str, dst_dir: str, kept_filenames: List[str]) -> None:
    os.makedirs(dst_dir, exist_ok=True)
    for fn in kept_filenames:
        in_path = os.path.join(src_dir, fn)
        try:
            with open(in_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"[WARN] Could not render Markdown for {fn}: {e}")
            continue
        md = render_markdown_for_event(data)
        base = os.path.splitext(fn)[0] + ".md"
        out_path = os.path.join(dst_dir, base)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(md)

def filter_json_by_tokens(args):
    """
    Filters a directory of JSON files based on token count, drops unlabeled,
    and optionally performs a stratified train/test split.
    Also writes Markdown reports for the kept files into a parallel directory tree.
    """
    # --- 1. Setup and Configuration ---
    input_dir = args.input_dir
    output_dir = args.output_dir
    max_len = args.max_context_length
    tokenizer_model = args.tokenizer_model

    overhead_config = {
        "prompt_overhead": 400,
        "output_buffer": 120,
        "variance_percentage": 0.10,
    }

    # --- 2. Calculate Threshold and Load Tokenizer ---
    try:
        print(f"Loading reference tokenizer: '{tokenizer_model}'...")
        tokenizer = AutoTokenizer.from_pretrained(tokenizer_model, use_fast=True)
        safe_token_threshold = calculate_safe_threshold(max_len, overhead_config)
    except Exception as e:
        print(f"Error: Could not load tokenizer or calculate threshold. {e}")
        return

    # --- 3. Prepare Directories ---
    if not os.path.isdir(input_dir):
        print(f"Error: Input directory '{input_dir}' not found.")
        return

    # We will (re)create output_dir with two parallel trees:
    #   {output_dir}/filtered_json/(train|test|root)
    #   {output_dir}/filtered_md/(train|test|root)
    ensure_clean_dir(output_dir)
    json_root = os.path.join(output_dir, "filtered_json")
    md_root   = os.path.join(output_dir, "filtered_md")
    os.makedirs(json_root, exist_ok=True)
    os.makedirs(md_root, exist_ok=True)

    # Try to read labels from a manifest in the input_dir
    manifest_in = os.path.join(input_dir, "manifest.jsonl")
    idx = read_manifest_labels(manifest_in)

    # --- 4. Scan, label-filter, and token-filter ---
    print(f"Scanning files in '{input_dir}'...")
    json_files = [f for f in os.listdir(input_dir) if f.endswith('.json')]
    if not json_files:
        print("No JSON files found in the input directory.")
        return

    total_files = 0
    labeled_candidates: List[Tuple[str, str]] = []  # (filename, label_id) BEFORE token filter
    kept_pairs: List[Tuple[str, str]] = []          # AFTER token filter

    for filename in tqdm(sorted(json_files), desc="Evaluating JSONs"):
        total_files += 1
        file_path = os.path.join(input_dir, filename)

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except json.JSONDecodeError:
            print(f"\n[WARN] Skipping corrupted JSON file: {filename}")
            continue
        except Exception as e:
            print(f"\n[WARN] Error reading file {filename}: {e}")
            continue

        # Label extraction (drop undefined/missing)
        lab = get_label_for_file(filename, idx, data)
        if not lab:
            # drop unlabeled or undefined
            continue
        lid, _ = lab
        labeled_candidates.append((filename, lid))

        # Tokenize minified JSON for consistency
        content_string = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
        tokens = tokenizer(content_string, add_special_tokens=False).input_ids
        token_count = len(tokens)

        if token_count <= safe_token_threshold:
            kept_pairs.append((filename, lid))

    # --- 5. Copy Kept Files + Generate Markdown (optionally stratified split) ---
    # Print label stats: before vs after filtering
    print_label_stats("Labeled BEFORE token filter", labeled_candidates)
    print_label_stats("Labeled AFTER token filter", kept_pairs)

    kept_filenames = [fn for fn, _ in kept_pairs]

    if args.split:
        test_size = args.test_size
        seed = args.seed

        train_pairs, test_pairs = stratified_split(kept_pairs, test_size=test_size, seed=seed)
        train_files = [fn for fn, _ in train_pairs]
        test_files  = [fn for fn, _ in test_pairs]

        # Prepare dirs
        train_json_dir = os.path.join(json_root, "train")
        test_json_dir  = os.path.join(json_root, "test")
        train_md_dir   = os.path.join(md_root, "train")
        test_md_dir    = os.path.join(md_root, "test")
        os.makedirs(train_json_dir, exist_ok=True)
        os.makedirs(test_json_dir, exist_ok=True)
        os.makedirs(train_md_dir, exist_ok=True)
        os.makedirs(test_md_dir, exist_ok=True)

        # Copy JSONs
        copy_kept_jsons(input_dir, train_json_dir, train_files)
        copy_kept_jsons(input_dir, test_json_dir,  test_files)

        # Write MDs
        write_markdowns(input_dir, train_md_dir, train_files)
        write_markdowns(input_dir, test_md_dir,  test_files)

        # Write manifests
        write_manifest(os.path.join(output_dir, "filtered_manifest.jsonl"), kept_pairs)
        write_manifest(os.path.join(train_json_dir, "manifest.jsonl"), train_pairs)
        write_manifest(os.path.join(test_json_dir,  "manifest.jsonl"), test_pairs)
        # (Optional) also mirror manifests into MD dirs for convenience
        write_manifest(os.path.join(train_md_dir, "manifest.jsonl"), train_pairs)
        write_manifest(os.path.join(test_md_dir,  "manifest.jsonl"), test_pairs)

        # Per-split stats
        print_label_stats("TRAIN split", train_pairs)
        print_label_stats("TEST split", test_pairs)

        print("\n--- Filtering + Stratified Split Complete ---")
        print(f"Total JSON files scanned: {total_files}")
        print(f"Total labeled (pre-filter): {len(labeled_candidates)}")
        print(f"Kept after token filter:    {len(kept_pairs)}")
        print(f"Train JSON: {len(train_files)}  → {train_json_dir}")
        print(f"Test  JSON: {len(test_files)}   → {test_json_dir}")
        print(f"Train MD:  {len(train_files)}  → {train_md_dir}")
        print(f"Test  MD:  {len(test_files)}   → {test_md_dir}")
        print(f"Filtered manifest: {os.path.join(output_dir, 'filtered_manifest.jsonl')}")
    else:
        # No split: dump all kept to root subdirs
        flat_json_dir = json_root
        flat_md_dir   = md_root
        os.makedirs(flat_json_dir, exist_ok=True)
        os.makedirs(flat_md_dir,   exist_ok=True)

        copy_kept_jsons(input_dir, flat_json_dir, kept_filenames)
        write_markdowns(input_dir, flat_md_dir, kept_filenames)

        write_manifest(os.path.join(output_dir, "filtered_manifest.jsonl"), kept_pairs)
        # mirror manifest to both trees for convenience
        write_manifest(os.path.join(flat_json_dir, "manifest.jsonl"), kept_pairs)
        write_manifest(os.path.join(flat_md_dir,   "manifest.jsonl"), kept_pairs)

        print("\n--- Filtering Complete (no split) ---")
        print(f"Total JSON files scanned: {total_files}")
        print(f"Total labeled (pre-filter): {len(labeled_candidates)}")
        print(f"Kept after token filter:    {len(kept_pairs)}")
        print(f"Filtered JSON: '{flat_json_dir}'")
        print(f"Filtered MD:   '{flat_md_dir}'")
        print(f"Filtered manifest: {os.path.join(output_dir, 'filtered_manifest.jsonl')}")

def main():
    parser = argparse.ArgumentParser(
        description="Filter JSONs by token count (single tokenizer), drop unlabeled, optionally stratify split, and emit Markdown twins.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('--input_dir', type=str,
                        default="/Users/murathanku/PycharmProjects/Cyber/pass2/snapshots_both/2025-08-20/simplified/",
                        help="Directory with simplified JSON files (and optional manifest.jsonl).")

    parser.add_argument('--output_dir', default="/Users/murathanku/PycharmProjects/Cyber/pass2/snapshots_both/2025-08-20/filtered-text",
                        help="Output directory. Will contain filtered_json/ and filtered_md/ (and train/test if split).")

    parser.add_argument('--max_context_length', type=int, default=8192, help="Fixed context window.")
    parser.add_argument('--tokenizer_model', type=str, default='meta-llama/Meta-Llama-3-8B-Instruct',
                        help="HF model name for tokenization.")
    parser.add_argument('--split', action='store_true', help="If set, perform a stratified train/test split.")
    parser.add_argument('--test_size', type=float, default=0.3,
                        help="Test set ratio when --split is used (default: 0.3).")
    parser.add_argument('--seed', type=int, default=42,
                        help="Random seed for deterministic stratified split (default: 42).")
    args = parser.parse_args()
    filter_json_by_tokens(args)

if __name__ == '__main__':
    main()
