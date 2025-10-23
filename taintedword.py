#!/usr/bin/env python3
"""
taintedword.py — Heuristic DOCX provenance scorer
Origins: Microsoft Word, LibreOffice, Google Docs, Apple Pages, Pandoc

Usage:
    python taintedword.py <file.docx> [--json]
"""

import argparse
import zipfile
import xml.etree.ElementTree as ET
import json
import sys
import re

NAMESPACES = {
    "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
}

# --- ZIP & XML helpers -------------------------------------------------------

def read_xml_from_zip(zf, name):
    try:
        with zf.open(name) as f:
            return ET.fromstring(f.read())
    except KeyError:
        return None

def read_text_from_zip(zf, name):
    try:
        with zf.open(name) as f:
            return f.read().decode("utf-8", "ignore")
    except KeyError:
        return ""

def xml_to_text(root):
    if root is None:
        return ""
    return ET.tostring(root, encoding="utf-8").decode("utf-8", "ignore")

# --- LibreOffice signals -----------------------------------------------------

def lo_checks(zf, parts):
    score, ev = 0.0, []
    app_xml = parts["app_xml"]
    if app_xml is not None:
        for elem in app_xml.iter():
            if elem.tag.endswith("Application"):
                val = (elem.text or "").lower()
                if "libreoffice" in val:
                    score += 6
                    ev.append("Application tag indicates LibreOffice")
                break
    font_txt = parts["font_txt"]
    if any(f in font_txt for f in ["Liberation", "Noto", "Lohit"]):
        score += 3
        ev.append("LibreOffice font families present (Liberation/Noto/Lohit)")
    if "<w:panose1" not in font_txt and "<w:sig" not in font_txt and font_txt:
        ev.append("No <w:panose1> or <w:sig> font fingerprints (often present in Word)")
    doc_txt = parts["doc_txt"]
    if "<w:formProt" in doc_txt:
        score += 3
        ev.append("Found <w:formProt> (LibreOffice hallmark)")
    styles_txt = parts["styles_txt"]
    if styles_txt:
        try:
            styles_root = parts["styles_xml"]
            names = [s.get(f"{{{NAMESPACES['w']}}}styleId", "").lower()
                     for s in styles_root.findall("w:style", NAMESPACES)]
            if any(n in names for n in ["text body", "standard", "heading", "index"]):
                score += 3
                ev.append("Found LibreOffice-style names (Text Body / Standard)")
        except Exception:
            pass
        if any(f in styles_txt for f in ["Liberation Sans", "Liberation Serif", "Noto Sans", "Lohit"]):
            score += 3
            ev.append("LibreOffice font families referenced in styles")
    settings_txt = parts["settings_txt"]
    if "<w:autoHyphenation" in settings_txt:
        score += 0.5
        ev.append("Contains <w:autoHyphenation> (possible LO default)")
    ct_txt = parts["content_types_txt"]
    if any(m in ct_txt for m in ["image/png", "image/jpeg"]):
        score += 1
        ev.append("Lists extra image MIME types (often seen in LO)")
    custom_txt = parts["custom_props_txt"]
    if "<vt:bool>0</vt:bool>" in custom_txt or "<vt:bool>1</vt:bool>" in custom_txt:
        score += 0.2
        ev.append("Boolean serialization uses numeric form (LibreOffice style)")
    if "vt:lpwstr" in custom_txt and "$Linux_" in custom_txt:
        score += 0.3
        ev.append("AppVersion property includes LibreOffice/Linux signature")
    core_txt = parts["core_txt"]
    if ("schemas.openxmlformats.org/officeDocument/2006/bibliography" in core_txt
            and "schemas.microsoft.com/office" not in core_txt):
        score += 0.4
        ev.append("Open bibliography schema without Microsoft URIs (LO-style rewrite)")
    return min(score, 10.0), ev

# --- Google Docs signals -----------------------------------------------------

def gdocs_checks(zf, parts):
    score, ev = 0.0, []
    styles_txt = parts["styles_txt"]
    font_txt = parts["font_txt"]
    if 'w:semiHidden w:val="1"' in styles_txt or 'w:unhideWhenUsed w:val="1"' in styles_txt:
        score += 2.0
        ev.append("Boolean attributes serialized as w:val='1' (Google Docs pattern)")
    if re.search(r'w:w="[\d]+\.[\d]+"', styles_txt):
        score += 1.5
        ev.append("Decimal-style numeric attributes (e.g., w:w='0.0') found")
    lower_hex = bool(re.search(r'w:color w:val="[0-9a-f]{6}"', styles_txt))
    if lower_hex:
        ev.append("Lowercase 6-digit hex color codes (weak Google Docs pattern)")
    has_symex = ("word/2015/wordml/symex" in styles_txt or "w16se" in styles_txt)
    if has_symex:
        ev.append("Contains w16se:symex namespace (weak marker; Word may include)")
    fonts_hit = False
    if re.search(r'w:font[^>]+name="Play"', font_txt) or "Play Bold" in font_txt:
        score += 3.0
        fonts_hit = True
        ev.append("Contains Play / Play Bold fonts (Google bundle)")
    if any(f in font_txt for f in ["Roboto", "Noto Sans", "Noto Serif"]):
        score += 1.5
        fonts_hit = True
        ev.append("Contains Roboto/Noto font families (Google pattern)")
    if (lower_hex or has_symex) and (fonts_hit or score >= 2.5):
        if lower_hex:
            score += 0.5
        if has_symex:
            score += 0.5
    return min(score, 10.0), ev

# --- Apple Pages signals -----------------------------------------------------

def pages_checks(zf, parts):
    score, ev = 0.0, []
    theme_txt = parts["theme_txt"]
    app_core_txt = (parts["app_txt"] + parts["core_txt"])
    if "Helvetica Neue" in theme_txt:
        score += 4.5
        ev.append("Contains Helvetica Neue (Apple Pages default font)")
    if "<a:theme" in theme_txt and "Office Theme" in theme_txt and "xmlns:thm15" not in theme_txt:
        score += 1.5
        ev.append("Missing thm15 theme namespace (Pages-style theme)")
    if "<a:srgbClr" in theme_txt and "<a:sysClr" not in theme_txt:
        score += 1.0
        ev.append("Theme uses only <a:srgbClr> (no <a:sysClr>)")
    if "<a:objectDefaults>" not in theme_txt or "<a:extLst>" not in theme_txt:
        if score >= 1.5:
            score += 0.5
            ev.append("No <a:objectDefaults> or <a:extLst> (weak Pages indicator)")
    if re.search(r"\bApple\b|\bPages\b", app_core_txt):
        score += 3.5
        ev.append("Explicit Apple/Pages marker in metadata")
    return min(score, 10.0), ev

# --- Pandoc / Programmatic signals ------------------------------------------

def pandoc_checks(zf, parts):
    score, ev = 0.0, []
    app_txt = parts["app_txt"]
    core_txt = parts["core_txt"]
    styles_txt = parts["styles_txt"]
    theme_txt = parts["theme_txt"]
    doc_txt = parts["doc_txt"]
    font_txt = parts["font_txt"]

    # Explicit Pandoc mention
    if re.search(r"pandoc", (app_txt + core_txt), re.I):
        score += 8
        ev.append("Application or core properties mention Pandoc")

    # Programmatic minimalism
    if not any(tag in app_txt for tag in ["Application", "AppVersion", "Company"]) and app_txt.strip():
        score += 1.5
        ev.append("App properties minimal (likely programmatic generation)")

    # Semantic style names
    if re.search(r"styleId=\"SourceCode\"|styleId=\"VerbatimChar\"", styles_txt):
        score += 2.5
        ev.append("Contains 'SourceCode' / 'VerbatimChar' styles (Pandoc hallmark)")
    if re.search(r"styleId=\"KeywordTok\"|styleId=\"StringTok\"|styleId=\"CommentTok\"", styles_txt):
        score += 2.0
        ev.append("Contains Pygments token styles (Pandoc code highlighting)")

    # Theme simplification
    if "xmlns:thm15" not in theme_txt and "<a:srgbClr" in theme_txt and "<a:sysClr" not in theme_txt:
        score += 1.5
        ev.append("Theme lacks thm15 namespace, uses only sRGB colors (Pandoc minimal theme)")

    # Fonts
    if all(f in font_txt for f in ["Calibri", "Cambria"]) and not any(x in font_txt for x in ["Aptos", "Liberation", "Roboto"]):
        score += 1.0
        ev.append("Generic Calibri/Cambria font table (typical Pandoc default)")

    # No rsid / mc:Ignorable
    if "rsidR" not in doc_txt and "mc:Ignorable" not in doc_txt:
        score += 1.0
        ev.append("Document XML lacks Word-specific rsid and mc:Ignorable attributes")

    # Web settings
    web_txt = read_text_from_zip(zf, "word/webSettings.xml")
    if "<w:doNotSaveAsSingleFile" in web_txt and "optimizeForBrowser" not in web_txt:
        score += 0.8
        ev.append("Contains <w:doNotSaveAsSingleFile> without optimizeForBrowser (Pandoc default)")

    # Missing latent styles
    if "<w:latentStyles" not in styles_txt and "<w:styleId=\"Normal\"" in styles_txt:
        score += 0.8
        ev.append("Missing <w:latentStyles> (common in Pandoc-generated DOCX)")

    # Behavioral round-trip fidelity heuristics
    if doc_txt.count("<w:r>") < 2 * doc_txt.count("<w:p>"):
        score += 0.8
        ev.append("Low <w:r>/<w:p> ratio (flattened run structure typical of Pandoc)")
    if "<w:pPr>" in doc_txt and not any(k in doc_txt for k in ["w:spacing", "w:ind", "w:contextualSpacing"]):
        score += 0.5
        ev.append("Paragraph properties minimal (no spacing/indent attributes)")
    if "Lucida" in font_txt and "Cambria Math" not in font_txt:
        score += 0.5
        ev.append("Math font substitution (Lucida instead of Cambria Math)")
    if any(c in theme_txt for c in ["4F81BD", "C0504D", "9BBB59", "8064A2", "4BACC6", "F79646"]):
        score += 0.5
        ev.append("Classic Office 2007 color palette (Pandoc default theme)")
    if re.search(r"<dc:creator\s*/>|<cp:lastModifiedBy>\s*</cp:lastModifiedBy>", core_txt):
        score += 0.5
        ev.append("Empty author/modified fields (metadata stripped by Pandoc)")

    return min(score, 10.0), ev

# --- WordPad signals --------------------------------------------------------

def wordpad_checks(zf, parts):
    """Heuristic detection of WordPad-generated DOCX files."""
    score, ev = 0.0, []

    # WordPad omits theme, fontTable, settings, and most docProps.
    content_types = parts["content_types_txt"]
    has_theme = "/word/theme/theme1.xml" in content_types
    has_settings = "/word/settings.xml" in content_types
    has_fonts = "/word/fontTable.xml" in content_types
    if not has_theme and not has_settings and not has_fonts:
        score += 3
        ev.append("Content_Types.xml lacks theme/settings/fontTable overrides (WordPad pattern)")

    # Styles.xml is tiny (1–10 lines) and only has 'Normal'
    styles_txt = parts["styles_txt"]
    if 0 < len(styles_txt.splitlines()) < 10 and "<w:styleId=\"Normal\"" in styles_txt:
        score += 3
        ev.append("Tiny styles.xml with only 'Normal' style (WordPad hallmark)")

    # document.xml: very simple namespaces and structure
    doc_txt = parts["doc_txt"]
    if (
        '<w:document xmlns:w=' in doc_txt
        and 'xmlns:r=' not in doc_txt
        and 'xmlns:mc=' not in doc_txt
    ):
        score += 3
        ev.append("Document XML uses only xmlns:w (minimal namespace set typical of WordPad)")

    # Missing metadata
    if not parts["app_txt"] and not parts["core_txt"]:
        score += 1
        ev.append("No app/core properties (WordPad omits docProps entirely)")

    return min(score, 10.0), ev


# --- TextEdit signals --------------------------------------------------------

def textedit_checks(zf, parts):
    """Heuristic detection of Apple TextEdit–generated DOCX files."""
    score, ev = 0.0, []

    content_types = parts["content_types_txt"]
    app_txt = parts["app_txt"]
    core_txt = parts["core_txt"]
    doc_txt = parts["doc_txt"]
    theme_txt = parts["theme_txt"]

    # 1. [Content_Types].xml: theme present but NO styles/settings/fontTable/etc.
    #    TextEdit keeps /word/theme/theme1.xml but strips nearly everything else.
    if (
        "/word/theme/theme1.xml" in content_types
        and "/word/styles.xml" not in content_types
        and "/word/settings.xml" not in content_types
        and "/word/fontTable.xml" not in content_types
        and "/word/numbering.xml" not in content_types
    ):
        score += 3
        ev.append("Has theme but lacks styles/settings/fontTable/numbering (TextEdit pattern)")

    # 2. docProps/app.xml: usually just an empty <Properties> element
    if app_txt.strip().startswith("<Properties") and "<Application>" not in app_txt:
        score += 3
        ev.append("app.xml is empty <Properties> with no <Application> tag (TextEdit hallmark)")

    # 3. docProps/core.xml: rewritten with 'cp:' prefix and only <dc:creator>
    if (
        "<cp:coreProperties" in core_txt
        and core_txt.count("<dc:") == 1
        and "<lastModifiedBy>" not in core_txt
        and "<revision>" not in core_txt
    ):
        score += 2
        ev.append("core.xml uses cp: prefix and only dc:creator (TextEdit serialization)")

    # 4. document.xml: stripped to basic w:, r:, v:, wp: namespaces; no w14+, mc:, w15 etc.
    if (
        "xmlns:w=" in doc_txt
        and all(x not in doc_txt for x in ["xmlns:mc=", "xmlns:w14=", "xmlns:w15=", "xmlns:w16="])
        and '<w:rFonts w:ascii="Times"' in doc_txt
    ):
        score += 2
        ev.append("document.xml limited to base namespaces and hardcoded Times font")

    # 5. Theme name: "Default Theme" instead of "Office Theme"
    if "name=\"Default Theme\"" in theme_txt:
        score += 1
        ev.append("Theme1.xml uses name='Default Theme' (TextEdit theme rewrite)")

    # 6. Overall metadata: no custom.xml, no customProps, no extended app info
    if (
        "/docProps/custom.xml" not in content_types
        and "/customXml/" not in content_types
        and "<Template>" not in app_txt
    ):
        score += 1
        ev.append("No customXml or extended properties (TextEdit metadata purge)")

    return min(score, 10.0), ev


# --- Microsoft Word confidence ----------------------------------------------

def word_checks(zf, parts, lo_score, gd_score, pg_score):
    score, ev = 0.0, []
    app_xml = parts["app_xml"]
    if app_xml is not None:
        for elem in app_xml.iter():
            if elem.tag.endswith("Application"):
                val = (elem.text or "").lower()
                if "word" in val:
                    score += 4.0
                    ev.append("Application tag indicates Microsoft Word")
                break
    theme_txt = parts["theme_txt"]
    font_txt = parts["font_txt"]
    styles_txt = parts["styles_txt"]
    if "xmlns:thm15" in theme_txt:
        score += 1.5
        ev.append("Theme includes thm15 namespace (common in Word)")
    if "<a:sysClr" in theme_txt:
        score += 1.0
        ev.append("Theme uses <a:sysClr> (Windows system color mapping)")
    if "<w:panose1" in font_txt or "<w:sig" in font_txt:
        score += 1.0
        ev.append("Font table includes <w:panose1> / <w:sig> fingerprints (Word)")
    if re.search(r'Heading1|Heading2|Heading3', styles_txt):
        score += 0.8
        ev.append("Heading1–3 style cascade present (Word defaults)")
    if lo_score < 4 and gd_score < 4 and pg_score < 4:
        score += 1.2
        ev.append("No strong non-Word indicators (boosting Word confidence)")
        
    # --- DEBUG robust python-docx [Content_Types].xml order detector ----------
    # --- python-docx [Content_Types].xml ordering heuristic -------------------
    try:
        raw = parts["content_types_txt"]
        root = ET.fromstring(raw)
        overrides = [elem.attrib.get("PartName", "") for elem in root if elem.tag.endswith("Override")]

        if "/word/document.xml" in overrides:
            # find last /docProps/* and first /word/* entries
            docprops_last = max((i for i, p in enumerate(overrides) if p.startswith("/docProps/")), default=-1)
            word_first = next((i for i, p in enumerate(overrides) if p.startswith("/word/")), None)

            if docprops_last >= 0 and word_first is not None and docprops_last < word_first:
                score -= 0.3
                ev.append(
                    "Override order in [Content_Types].xml shows docProps before /word/document.xml "
                    "(python-docx generation pattern; small deduction)"
                )
    except Exception:
        pass





    return min(score, 10.0), ev
    
def onlyoffice_checks(doc_text, evidence):
    """
    Detect signatures of OnlyOffice-generated DOCX files.

    Returns:
        float: normalized score (0–10)
    """
    import re
    score = 0


    for m in re.findall(r'<w:tblCellSpacing[^>]*w:w="(\d+)"', doc_text):
        val = int(m)
        if val % 1134 in range(0, 10):
            evidence.append(f"Table cell spacing → doubled mm/twip conversion (OnlyOffice).")
            score += 2
            break

    tbl_layouts = len(re.findall(r'<w:tblLayout[^>]*w:type="fixed"', doc_text))
    if tbl_layouts >= 3:
        evidence.append(f"{tbl_layouts} tables forced to fixed layout (OnlyOffice default).")
        score += 2

    if re.search(r'<w:tblLook[^>]*w:val="0[4-7][A-F0-9]{2}"', doc_text):
        evidence.append("Nonstandard <w:tblLook> bitmask (OnlyOffice bit flag composition).")
        score += 2


    if re.search(r'<w:tblW[^>]*>\s*<w:tblStyle', doc_text):
        evidence.append("<w:tblW> precedes <w:tblStyle> (OnlyOffice ordering).")
        score += 1
    if re.search(r'<w:tblBorders[^>]*>\s*<w:tblLayout', doc_text):
        evidence.append("<w:tblBorders> precedes <w:tblLayout> (OnlyOffice ordering).")
        score += 1

    for m in re.findall(r'w:w="(\d+)"', doc_text):
        v = int(m)
        if v % 5 not in (0, 5) and v % 10 != 0:
            evidence.append(f"Non-rounded twip {v} — float→int mm rounding (OnlyOffice).")
            score += 1
            break

    if "<w:tblLayout" in doc_text and "mc:Ignorable" not in doc_text:
        evidence.append("tblLayout present but missing mc:Ignorable (OnlyOffice omission).")
        score += 1

    if re.search(r'<w:(tbl|tr|tc|p|r)PrChange', doc_text) and "<w:trackChange" not in doc_text:
        evidence.append("Inline *PrChange blocks without trackChange (OnlyOffice-style revisions).")
        score += 2

    if '<w:numId w:val="0"' in doc_text and '<w:abstractNumId' not in doc_text:
        evidence.append("<w:numId w:val='0'> without abstractNum (OnlyOffice numbering map leak).")
        score += 1
    if "<w:lvlOverride" in doc_text and "<w:startOverride" not in doc_text:
        evidence.append("<w:lvlOverride> without startOverride (OnlyOffice list export artifact).")
        score += 1

    if "<w:headerReference" in doc_text and "<w:evenAndOddHeaders" not in doc_text:
        evidence.append("Header refs but no evenAndOddHeaders — pre-v5 OnlyOffice schema.")
        score += 1
    if "<w:sectPr" in doc_text and "<w:titlePg" not in doc_text:
        evidence.append("Sections present but missing titlePg — older OnlyOffice export (<v5).")
        score += 1

    if re.search(r'itemProps\d+\.xml', doc_text) or re.search(r'(formid=|glossaryid=|jsaproject)', doc_text, re.I):
        evidence.append("References to OForm/Glossary/JSA — OnlyOffice extensions.")
        score += 2

    if "xmlns:wps" not in doc_text and "drawing" in doc_text:
        evidence.append("Missing wps/wpg drawing namespaces (OnlyOffice omission).")
        score += 1
        

    return min(score, 10.0)

    
# --- Word variants: Desktop vs Web ------------------------------------------

def word_variants_checks(zf, parts):
    """Distinguish Word for the Web vs. Desktop Word based on app/core/theme/features."""
    score = {"word_web": 0.0, "word_desktop": 0.0}
    ev = {"word_web": [], "word_desktop": []}

    app_txt = parts["app_txt"]
    core_txt = parts["core_txt"]
    theme_txt = parts["theme_txt"]
    font_txt = parts["font_txt"]
    styles_txt = parts["styles_txt"]
    settings_txt = parts["settings_txt"]
    doc_txt = parts["doc_txt"]

    # Application tag check
    if "Microsoft Word for the web" in app_txt:
        score["word_web"] += 6
        ev["word_web"].append("<Application>Microsoft Word for the web</Application> detected")

    if "Microsoft Office Word" in app_txt:
        score["word_desktop"] += 6
        ev["word_desktop"].append("<Application>Microsoft Office Word</Application> detected")

    # Font table clues
    if "Aptos" in font_txt:
        score["word_desktop"] += 2
        ev["word_desktop"].append("Aptos/Aptos Display font (new Word 2024 default)")
    if "Calibri" in font_txt and "Aptos" not in font_txt:
        score["word_web"] += 1.5
        ev["word_web"].append("Legacy Calibri font (Word Web or pre-2024 Word)")

    # Theme clues
    if "xmlns:thm15" in theme_txt:
        score["word_web"] += 1
        ev["word_web"].append("Theme includes thm15 namespace (Word Web)")
    if "w16du" in theme_txt or "w16du" in settings_txt:
        score["word_desktop"] += 1.5
        ev["word_desktop"].append("Modern WordML namespaces (Word 2023/2024 Desktop)")

    # Fragmented run structure
    if doc_txt.count("<w:r>") > 3 * doc_txt.count("<w:p>"):
        score["word_web"] += 1.5
        ev["word_web"].append("Highly fragmented <w:r> structure (Word for Web pattern)")
    else:
        score["word_desktop"] += 0.5
        ev["word_desktop"].append("Compact run structure (Desktop Word)")

    # Revision / metadata depth
    if "<cp:revision>" in core_txt:
        score["word_desktop"] += 1
        ev["word_desktop"].append("Core properties include <cp:revision> (Desktop Word)")
    else:
        score["word_web"] += 0.5
        ev["word_web"].append("No revision property (Word Web minimal metadata)")

    # Normalize
    for k in score:
        score[k] = min(score[k], 10.0)
    return score, ev


# --- Final verdict logic -----------------------------------------------------

def choose_verdict(scores):
    non_word = {k: v for k, v in scores.items() if k != "word"}
    top_origin = max(non_word, key=non_word.get)
    top_val = non_word[top_origin]
    word_val = scores["word"]
    if top_val >= 7:
        return f"Definitely {label(top_origin)} export"
    if top_val >= 5:
        return f"Likely {label(top_origin)} export or mixed"
    if word_val >= 7 and top_val < 4:
        return "Pure Microsoft Word"
    if word_val >= 5 and top_val < 5:
        return "Probably Microsoft Word (minor artifacts present)"
    return "Inconclusive / mixed"

def label(key):
    return {
        "libreoffice": "LibreOffice",
        "google_docs": "Google Docs",
        "apple_pages": "Apple Pages",
        "word": "Microsoft Word",
        "pandoc": "Pandoc / programmatic",
        "wordpad": "WordPad",
        "textedit": "TextEdit",
    }[key]
    
def summarize_provenance(result):
    """Return a richer human-friendly summary paragraph."""
    verdict = result["verdict"]
    word_variants = result.get("word_variants", {}).get("scores", {})
    likely_variant = None
    if word_variants.get("word_web", 0) > word_variants.get("word_desktop", 0):
        likely_variant = "Word for the Web"
    elif word_variants.get("word_desktop", 0) > 0:
        likely_variant = "Word Desktop"
    lines = [f"Overall verdict: {verdict}."]
    if likely_variant:
        lines.append(f"Within Microsoft Word, this document most closely matches **{likely_variant}** patterns.")
    lines.append("Heuristics examined include font defaults, XML namespaces, and application metadata.")
    return " ".join(lines)
    
    
# much more speculative right now...
# todo: integrate!
def check_speculative_wordaspect(zf):
    score, ev = 0, []
    for name in zf.namelist():
        if name.startswith("webextensions/"):
            score += 3
            ev.append(f"Contains {name} (Word 365 Web add-in structure)")
        if "sharepoint.com" in name.lower():
            score += 5
            ev.append(f"References SharePoint URL in relationships: {name}")
    core = read_text_from_zip(zf, "docProps/core.xml")
    if re.search(r"https://.*sharepoint\.com", core, re.I):
        score += 4
        ev.append("SharePoint reference found in core properties")
    if re.search(r"Microsoft Office Word", core):
        score += 1
        ev.append("Application tag suggests Office Online editor")
    return min(score, 10), ev

def check_speculative_lomarkeshare(xml_bundle):
    """
    Blind heuristic scorer for 'other' DOCX sources:
    WPS Office, OnlyOffice, AbiWord, Calligra, WordPad, SoftMaker, Pandoc/docx4j/etc.
    Designed to detect origin when Application tag is missing or generic.
    
    Args:
        xml_bundle (dict): dictionary of raw XML text content keyed by filename, e.g.:
            {
                "app": <str>,
                "core": <str>,
                "font": <str>,
                "styles": <str>,
                "theme": <str>,
                "content": <str>,
            }
    
    Returns:
        dict: { "wps": score, "onlyoffice": score, "abiword": score,
                "calligra": score, "wordpad": score, "softmaker": score, "programmatic": score },
        list of (engine, evidence) tuples.
    """
    app, core, font, styles, theme, content = (
        xml_bundle.get("app", ""), xml_bundle.get("core", ""),
        xml_bundle.get("font", ""), xml_bundle.get("styles", ""),
        xml_bundle.get("theme", ""), xml_bundle.get("content", "")
    )
    


    scores = {
        "wps": 0.0,
        "onlyoffice": 0.0,
        "abiword": 0.0,
        "calligra": 0.0,
        "wordpad": 0.0,
        "softmaker": 0.0,
        "programmatic": 0.0,
    }
    evidences = []

    # --- WPS Office (Kingsoft)
    if any(x in (app + core).lower() for x in ["wps", "kingsoft", "wps office"]):
        scores["wps"] += 8
        evidences.append(("WPS Office", "Application metadata contains WPS/Kingsoft signature"))
    if "schemas.wps.cn" in (app + content + styles):
        scores["wps"] += 5
        evidences.append(("WPS Office", "Contains Chinese WPS-specific XML namespace"))
    if any(f in font for f in ["SimSun", "KaiTi", "FangSong"]):
        scores["wps"] += 2
        evidences.append(("WPS Office", "CJK font families common in WPS Office"))
    
    # --- AbiWord
    if "abiword" in (app + core).lower():
        scores["abiword"] += 8
        evidences.append(("AbiWord", "Application tag or creator field mentions AbiWord"))
    if "<a:theme" not in theme and "<w:docDefaults" in styles:
        scores["abiword"] += 3
        evidences.append(("AbiWord", "No theme.xml but includes simple docDefaults"))
    if "styleId=\"Normal\"" in styles and "Heading1" not in styles:
        scores["abiword"] += 1
        evidences.append(("AbiWord", "Single 'Normal' style without headings (AbiWord pattern)"))
    
    # --- Calligra Words
    if "calligra" in (app + core + content).lower():
        scores["calligra"] += 8
        evidences.append(("Calligra Words", "Application metadata indicates Calligra Words"))
    if "<w:compatSetting" not in content and "koffice" in (app + core).lower():
        scores["calligra"] += 2
        evidences.append(("Calligra Words", "No compatSetting + legacy KOffice marker"))
    
    # --- WordPad
    if "wordpad" in (app + core).lower():
        scores["wordpad"] += 8
        evidences.append(("WordPad", "Application tag indicates WordPad"))
    if "word/theme/theme1.xml" not in content and "<w:styleId=\"Normal\"" in styles and "<w:style" not in content[500:]:
        scores["wordpad"] += 3
        evidences.append(("WordPad", "No theme and only a 'Normal' style (WordPad pattern)"))
    
    # --- SoftMaker / FreeOffice (TextMaker)
    if "textmaker" in (app + core + content).lower():
        scores["softmaker"] += 8
        evidences.append(("TextMaker", "Application metadata includes TextMaker"))
    if "SoftMaker Office" in (core + content):
        scores["softmaker"] += 6
        evidences.append(("TextMaker", "Custom props mention SoftMaker Office"))
    
    # --- Programmatic / Automated DOCX (Pandoc, docx4j, Apache POI)
    if any(x in (app + core + content).lower() for x in ["pandoc", "docx4j", "aspose", "poi", "python-docx"]):
        scores["programmatic"] += 8
        evidences.append(("Programmatic", "Metadata references Pandoc/docx4j/Aspose"))
    if not any(f in (app + core + content) for f in ["Application", "AppVersion", "Company"]):
        scores["programmatic"] += 2
        evidences.append(("Programmatic", "No app metadata tags (generated by library)"))
    if "<w:themeFontLang" not in styles and "<w:lang" in content:
        scores["programmatic"] += 1.5
        evidences.append(("Programmatic", "Basic language tags without theme references (minimal DOCX structure)"))
     
     
    # --- OnlyOffice
    if "onlyoffice" in (app + core + content).lower():
        scores["onlyoffice"] += 8
        evidences.append(("OnlyOffice", "Application metadata references OnlyOffice"))
    if "onlyoffice.com/schema" in content:
        scores["onlyoffice"] += 4
        evidences.append(("OnlyOffice", "Contains OnlyOffice custom schema URI"))
    if "<w:latentStyles" not in styles:
        scores["onlyoffice"] += 1.5
        evidences.append(("OnlyOffice", "Missing latentStyles section (common in OnlyOffice exports)"))
       
    oo_ev = []
    oo_score = onlyoffice_checks(content, oo_ev)
    if oo_score >= 2:
        scores["onlyoffice"] = min(10.0, scores["onlyoffice"] + oo_score)
        for e in oo_ev:
            evidences.append(("OnlyOffice", e))

    # Normalize all scores to 10
    for k in scores:
        scores[k] = min(scores[k], 10.0)

    return scores, evidences



# todo: always declare the stated application so the user can see it!


# --- Scoring engine ----------------------------------------------------------

def score_docx(path):
    with zipfile.ZipFile(path) as zf:
        parts = {
            "app_xml": read_xml_from_zip(zf, "docProps/app.xml"),
            "font_xml": read_xml_from_zip(zf, "word/fontTable.xml"),
            "doc_xml": read_xml_from_zip(zf, "word/document.xml"),
            "styles_xml": read_xml_from_zip(zf, "word/styles.xml"),
            "settings_xml": read_xml_from_zip(zf, "word/settings.xml"),
            "theme_xml": read_xml_from_zip(zf, "word/theme/theme1.xml"),
            "content_types_txt": read_text_from_zip(zf, "[Content_Types].xml"),
            "custom_props_txt": read_text_from_zip(zf, "docProps/custom.xml"),
            "core_txt": read_text_from_zip(zf, "docProps/core.xml"),
            "app_txt": read_text_from_zip(zf, "docProps/app.xml"),
            "font_txt": read_text_from_zip(zf, "word/fontTable.xml"),
            "doc_txt": read_text_from_zip(zf, "word/document.xml"),
            "styles_txt": read_text_from_zip(zf, "word/styles.xml"),
            "settings_txt": read_text_from_zip(zf, "word/settings.xml"),
            "theme_txt": read_text_from_zip(zf, "word/theme/theme1.xml"),
        }
        lo_score, lo_ev = lo_checks(zf, parts)
        gd_score, gd_ev = gdocs_checks(zf, parts)
        pg_score, pg_ev = pages_checks(zf, parts)
        pd_score, pd_ev = pandoc_checks(zf, parts)
        wd_score, wd_ev = word_checks(zf, parts, lo_score, gd_score, pg_score)
        word_variant_scores, word_variant_ev = word_variants_checks(zf, parts)
        wp_score, wp_ev = wordpad_checks(zf, parts)
        te_score, te_ev = textedit_checks(zf, parts)

        scores = {
            "word": wd_score,
            "libreoffice": lo_score,
            "google_docs": gd_score,
            "apple_pages": pg_score,
            "pandoc": pd_score,
            "wordpad": wp_score,
            "textedit": te_score,
            
        }

        verdict = choose_verdict(scores)
        evidence = {
            "word": wd_ev,
            "libreoffice": lo_ev,
            "google_docs": gd_ev,
            "apple_pages": pg_ev,
            "pandoc": pd_ev,
            "wordpad": wp_ev,
            "textedit": te_ev,
        }

        taint_like = max(lo_score, gd_score, pg_score, pd_score)
        
        # Speculative checks (Word Web / SharePoint & other engines)
        wordweb_score, wordweb_ev = check_speculative_wordaspect(zf)

        lo_extras, lo_extra_ev = check_speculative_lomarkeshare({
            "app": parts["app_txt"],
            "core": parts["core_txt"],
            "font": parts["font_txt"],
            "styles": parts["styles_txt"],
            "theme": parts["theme_txt"],
            "content": parts["doc_txt"],
        })


        return {
            "scores": scores,
            "verdict": verdict,
            "taint": taint_like,
            "evidence": evidence,
            "word_variants": {
                "scores": word_variant_scores,
                "evidence": word_variant_ev,
            },
            "speculative": {
                "word_web": {
                    "score": wordweb_score,
                    "evidence": wordweb_ev,
                },
                "other_engines": {
                    "scores": lo_extras,
                    "evidence": lo_extra_ev,
                },
            },
        }


# --- CLI ---------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="Score DOCX provenance (Word, LibreOffice, Google Docs, Apple Pages, Pandoc)")
    p.add_argument("file", help="Path to .docx file")
    p.add_argument("--json", action="store_true", help="Output JSON report")
    p.add_argument("--concise", action="store_true", help="Say little.")
    args = p.parse_args()
    try:
        result = score_docx(args.file)
    except FileNotFoundError:
        print(f"Error: file not found: {args.file}", file=sys.stderr)
        sys.exit(1)
    except zipfile.BadZipFile:
        print(f"Error: not a valid DOCX file: {args.file}", file=sys.stderr)
        sys.exit(1)
    scores = result["scores"]
    verdict = result["verdict"]
    taint = result["taint"]
    evidence = result["evidence"]
    
    if args.concise:
        verdict2 = verdict.split()
        verdict = verdict2[0] if len(verdict2) < 2 else verdict2[1]
    
    if args.json:
        if args.concise:
            print(json.dumps({
                "verdict": verdict,
            }, indent=2))
        else:
            print(json.dumps({
                "file": args.file,
                "scores": scores,
                "verdict": verdict,
                "taint": taint,
                "evidence": evidence,
                "speculative": result.get("speculative", {})
            }, indent=2))
        return
        
    if args.concise:
        print(f"File: {verdict}")
        return


    print("Word Variant Summary:")
    print(summarize_provenance(result))
    print()

    print(f"{args.file}")
    print(f"Verdict: {verdict}")
    print("Scores (0–10):")
    print(f"  - Microsoft Word : {scores['word']:.1f}")
    print(f"  - LibreOffice    : {scores['libreoffice']:.1f}")
    print(f"  - Google Docs    : {scores['google_docs']:.1f}")
    print(f"  - Apple Pages    : {scores['apple_pages']:.1f}")
    print(f"  - Pandoc         : {scores['pandoc']:.1f}")
    print(f"  - WordPad        : {scores['wordpad']:.1f}")
    print(f"  - TextEdit        : {scores['textedit']:.1f}")
    
    print(f"\nTaint-like (max non-Word): {taint:.1f}/10\n")
    def show(block_name):
        evs = evidence.get(block_name) or []
        if evs:
            print(f"{label(block_name)} evidence:")
            for e in evs:
                print(f"  - {e}")
            print()
    show("word")
    show("libreoffice")
    show("google_docs")
    show("apple_pages")
    show("pandoc")
    show("wordpad")
    show("textedit")
    spec = result.get("speculative", {})
    ww = spec.get("word_web", {})
    if ww.get("score"):
        print(f"Speculative Word Web/SharePoint score: {ww['score']:.1f}")
        for e in ww.get("evidence", []):
            print(f"  - {e}")
        print()

    other = spec.get("other_engines", {})
    if other.get("scores"):
        print("Other-engine (conjectural, not sample-based) heuristic hits:")
        for k, v in other["scores"].items():
            if v >= 3:
                print(f"  - {k:12s}: {v:.1f}")
        for eng, ev in other.get("evidence", []):
            print(f"    • {eng}: {ev}")
        print()

    variants = result.get("word_variants", {})
    if variants:
        print("Word variant (Web vs Desktop) analysis:")
        for k, v in variants.get("scores", {}).items():
            if v > 0:
                print(f"  - {k:12s}: {v:.1f}")
        for var, evs in variants.get("evidence", {}).items():
            for e in evs:
                print(f"    • {var}: {e}")
        print()


if __name__ == "__main__":
    main()

