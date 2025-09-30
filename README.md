# Benchmarking LLMs for Threat Level Determination

*Dataset repo for threat-level determination from cybersecurity threat intelligence (CTI).*

---

## Repository Layout

```
scripts/           # data preparation scripts (download → simplify → filter/split)
frozen_snapshot/   # the snapshot used in the paper
```

---

## Create Your Own Snapshot

**0) Set up a virtual environment and install dependencies**

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**1) Download raw MISP OSINT events**

```bash
python scripts/download_events.py
# → writes JSONs + manifest.jsonl under: snapshot_<DATE>/raw/
```

**2) Simplify MISP JSON into a compact schema**

```bash
python scripts/simplify_misp.py   --input-dir  snapshot_<DATE>/raw/   --output-dir snapshot_<DATE>/simplified
# optional flags:
#   --truncate-long <N>    # 0 keeps full text (default)
#   --drop-to-ids          # drop attributes with to_ids=false
```

**3) Filter and (optionally) stratify into train/test**

```bash
python scripts/filter_and_split.py   --input-dir  snapshot_<DATE>/simplified/   --output-dir snapshot_<DATE>/prepared   --split
# useful flags:
#   --tokenizer_model meta-llama/Meta-Llama-3-8B-Instruct
#   --max_context_length 8192
#   --test_size 0.30
#   --seed 42
```

> If you omit `--split`, the script only filters and writes unsplit `filtered_json/` and `filtered_md/`.

---

## Resulting Structure

```
snapshot_<DATE>/
├─ raw/
│  ├─ <uuid>.json
│  └─ manifest.jsonl
├─ simplified/
│  └─ <uuid>.json
└─ prepared/
   ├─ filtered_manifest.jsonl
   ├─ filtered_json/
   │  ├─ train/*.json   # if --split
   │  └─ test/*.json
   └─ filtered_md/
      ├─ train/*.md     # if --split
      └─ test/*.md
```

---

## Script Reference (CLI)

### `download_events.py`

```text
usage: download_events.py [-h] [--out OUT] [--max-workers MAX_WORKERS]
```

### `simplify_misp.py`

```text
usage: simplify_misp.py [-h] --input-dir INPUT_DIR --output-dir OUTPUT_DIR
                        [--truncate-long TRUNCATE_LONG] [--drop-to-ids]
```

### `filter_and_split.py`

```text
usage: filter_and_split.py [-h] --input-dir INPUT_DIR --output-dir OUTPUT_DIR
                           [--max_context_length MAX_CONTEXT_LENGTH]
                           [--tokenizer_model TOKENIZER_MODEL]
                           [--split] [--test_size TEST_SIZE] [--seed SEED]
```

---

## Frozen Snapshot

The folder `frozen_snapshot/` contains the exact data used in the paper. Use it for reproducibility or for comparing your results against the baselines presented in our paper.

---

## Citation

Wang, Han, Murathan Kurfalı, and Alfonso Iacovazzi. *Benchmarking LLMs for Threat Level Determination*. **LLM4Sec 2025: The First Workshop on Large Language Models for Cybersecurity**, at the IEEE International Conference on Data Mining (ICDM) 2025, 2025.
