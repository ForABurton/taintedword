# 🧩 taintedword

> Heuristic **DOCX provenance analyzer** — guesses whether a `.docx` file came from **Microsoft Word**, **LibreOffice**, **Google Docs**, **Apple Pages**, **Pandoc**, **OnlyOffice**, **WordPad**, or **TextEdit** based on XML fingerprints.

[![Status: Experimental](https://img.shields.io/badge/status-experimental-orange.svg)](https://github.com/)
[![Type: Personal Project](https://img.shields.io/badge/type-personal-blueviolet.svg)](https://github.com/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)

---

## 📖 Overview

`taintedword.py` is a forensic utility that inspects the internal XML of `.docx` files (which are Open Packaging Convention ZIP archives) and applies a set of heuristic rules to infer which application generated them.

It doesn’t rely on digital signatures or metadata tags alone. Instead, it examines:
- **Font families** (e.g. Liberation, Roboto, Helvetica Neue)
- **XML namespaces** and tag structures
- **Application metadata** in `docProps/app.xml` and `core.xml`
- **Thematic and style information**
- **Low-level serialization quirks** specific to editors

---

## 🚀 Usage

### Basic command
```
python taintedword.py myfile.docx
```

### Options
```
  --json       Output full JSON report
  --concise    Print only a short verdict
```

Example:
```
$ python3 taintedword.py HelloWordDesktop.docx
Word Variant Summary:
Overall verdict: Pure Microsoft Word. Within Microsoft Word, this document most closely matches **Word Desktop** patterns. Heuristics examined include font defaults, XML namespaces, and application metadata.

HelloWordDesktop.docx
Verdict: Pure Microsoft Word
Scores (0–10):
  - Microsoft Word : 9.5
  - LibreOffice    : 0.0
  - Google Docs    : 0.0
  - Apple Pages    : 3.5
  - Pandoc         : 0.0
  - WordPad        : 0.0
  - TextEdit        : 0.0

Taint-like (max non-Word): 3.5/10

Microsoft Word evidence:
  - Application tag indicates Microsoft Word
  - Theme includes thm15 namespace (common in Word)
  - Theme uses <a:sysClr> (Windows system color mapping)
  - Font table includes <w:panose1> / <w:sig> fingerprints (Word)
  - Heading1–3 style cascade present (Word defaults)
  - No strong non-Word indicators (boosting Word confidence)

Google Docs evidence:
  - Lowercase 6-digit hex color codes (weak Google Docs pattern)
  - Contains w16se:symex namespace (weak marker; Word may include)

Other-engine (conjectural, not sample-based) heuristic hits:

Word variant (Web vs Desktop) analysis:
  - word_web    : 2.5
  - word_desktop: 10.0
    • word_web: Theme includes thm15 namespace (Word Web)
    • word_web: Highly fragmented <w:r> structure (Word for Web pattern)
    • word_desktop: <Application>Microsoft Office Word</Application> detected
    • word_desktop: Aptos/Aptos Display font (new Word 2024 default)
    • word_desktop: Modern WordML namespaces (Word 2023/2024 Desktop)
    • word_desktop: Core properties include <cp:revision> (Desktop Word)
```

JSON mode:
```
python taintedword.py file.docx --json
```

---


## 📦 Output Structure

When imported as a module:
```python
from taintedword import score_docx

result = score_docx("example.docx")
print(result["verdict"])
print(result["scores"])
```

`result` contains:
- `scores` → per-editor 0–10 scores (not empirical probabilities)  
- `verdict` → overall textual conclusion  
- `evidence` → list of matching heuristics  
- `word_variants` → Desktop vs. Web Word signals  
- `speculative` → OnlyOffice / WPS / other secondary engines (on the future sample roadmap)

---

## ⚠️ Limitations

- May be confused by heavily round-tripped files.  
- Not for certification or legal analysis.
- Obviously a lead-in to the spreadsheet version (taintedcell.py)

---

## 🧩 Example Verdicts

| Verdict | Meaning |
|----------|----------|
| `Pure Microsoft Word` | Confidently Word, no non-Word patterns |
| `Likely Google Docs export` | Most heuristics match Google Docs |
| `Probably Microsoft Word (minor artifacts present)` | Mostly Word, but contains traces of other tools |
| `Inconclusive / mixed` | No dominant engine detected |

---

## 🧰 Requirements

- Python 3.8+
- Standard library only (no external dependencies)

---

## 📄 License

Released under the **MIT License**.  
See `LICENSE` for details.

---



