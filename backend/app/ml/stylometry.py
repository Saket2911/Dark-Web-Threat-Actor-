"""Stylometric similarity.

Combines a TF-IDF cosine similarity over word and character n-grams with the
closeness of interpretable lexical features (sentence length, word length,
vocabulary diversity and punctuation profile). Returns a full explanation so
an analyst can see *why* two samples look similar or different.

Guards are included against the classic false positive: the same text (or a
shared template) being treated as independent evidence of identity.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Dict, Tuple

DEFAULT_MIN_WORDS = 20

FEATURE_KEYS = ("avg_sentence_length", "avg_word_length", "vocab_diversity")

PUNCTUATION_MARKS = ".,!?;:'\"-()[]"


def preprocess(text: str) -> str:
    text = text or ""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\s+", " ", text).strip()
    return text


def tokens(text: str):
    return re.findall(r"[a-zA-Z']+", preprocess(text).lower())


def extract_features(text: str) -> Dict:
    text = preprocess(text)
    sentences = [s for s in re.split(r"(?<=[.!?])\s+", text) if s.strip()]
    words = re.findall(r"\b\w+\b", text.lower())
    unique = set(words)
    punct = Counter(c for c in text if c in PUNCTUATION_MARKS)
    avg_sent = (sum(len(s.split()) for s in sentences) / len(sentences)) if sentences else 0.0
    avg_word = (sum(len(w) for w in words) / len(words)) if words else 0.0
    vocab = (len(unique) / len(words)) if words else 0.0
    total_punct = sum(punct.values()) or 1
    return {
        "avg_sentence_length": round(avg_sent, 3),
        "avg_word_length": round(avg_word, 3),
        "vocab_diversity": round(vocab, 3),
        "word_count": len(words),
        "unique_word_count": len(unique),
        "sentence_count": len(sentences),
        "punctuation": dict(punct),
        "punctuation_profile": {k: round(v / total_punct, 3) for k, v in punct.items()},
    }


def _tfidf_similarity(text_a: str, text_b: str) -> Tuple[float, list]:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity

    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2), sublinear_tf=True, min_df=1, lowercase=True
    )
    matrix = vectorizer.fit_transform([text_a, text_b])
    score = float(cosine_similarity(matrix[0], matrix[1])[0][0])
    names = vectorizer.get_feature_names_out()
    row_a = matrix[0].toarray()[0]
    row_b = matrix[1].toarray()[0]
    shared = [
        (names[i], round(float(row_a[i] * row_b[i]), 4))
        for i in range(len(names))
        if row_a[i] > 0 and row_b[i] > 0
    ]
    shared.sort(key=lambda item: item[1], reverse=True)
    return score, shared[:12]


def _feature_similarity(fa: Dict, fb: Dict) -> Tuple[float, Dict[str, float]]:
    diffs: Dict[str, float] = {}
    for key in FEATURE_KEYS:
        a, b = float(fa[key]), float(fb[key])
        scale = max(abs(a), abs(b), 1.0)
        diffs[key] = round(max(0.0, 1.0 - abs(a - b) / scale), 4)
    return sum(diffs.values()) / len(diffs), diffs


def _punctuation_similarity(fa: Dict, fb: Dict) -> float:
    marks = set(fa["punctuation_profile"]) | set(fb["punctuation_profile"])
    if not marks:
        return 1.0
    diff = sum(
        abs(fa["punctuation_profile"].get(m, 0.0) - fb["punctuation_profile"].get(m, 0.0))
        for m in marks
    )
    return max(0.0, 1.0 - diff / 2.0)


def stylometric_similarity(
    text_a: str,
    text_b: str,
    min_words: int = DEFAULT_MIN_WORDS,
) -> Tuple[float, Dict]:
    """Return ``(score, details)`` for two writing samples."""
    ta, tb = preprocess(text_a), preprocess(text_b)
    if not ta or not tb:
        return 0.0, {
            "reason": "missing text",
            "sufficient": False,
            "note": "Both samples must contain text to compare writing style.",
        }

    fa = extract_features(ta)
    fb = extract_features(tb)
    sufficient = fa["word_count"] >= min_words and fb["word_count"] >= min_words

    if not tokens(ta) or not tokens(tb):
        return 0.0, {
            "reason": "no alphabetic tokens",
            "sufficient": False,
            "features_a": fa,
            "features_b": fb,
            "note": "Samples contain no comparable words.",
        }

    tfidf_score, shared_terms = _tfidf_similarity(ta, tb)
    feature_score, feature_diffs = _feature_similarity(fa, fb)
    punct_score = _punctuation_similarity(fa, fb)

    lexical = 0.7 * feature_score + 0.3 * punct_score
    score = 0.55 * tfidf_score + 0.45 * lexical

    identical = re.sub(r"\W+", " ", ta.lower()).strip() == re.sub(r"\W+", " ", tb.lower()).strip()
    if identical:
        score = max(score, 0.99)

    comparisons = []
    if fa["avg_sentence_length"] and fb["avg_sentence_length"]:
        delta = abs(fa["avg_sentence_length"] - fb["avg_sentence_length"])
        comparisons.append(
            {
                "feature": "sentence_length",
                "a": fa["avg_sentence_length"],
                "b": fb["avg_sentence_length"],
                "closeness": feature_diffs["avg_sentence_length"],
                "note": f"Average sentence length differs by {delta:.1f} words.",
            }
        )
    comparisons.append(
        {
            "feature": "vocabulary_diversity",
            "a": fa["vocab_diversity"],
            "b": fb["vocab_diversity"],
            "closeness": feature_diffs["vocab_diversity"],
            "note": "Type/token ratio; sensitive to sample length.",
        }
    )
    comparisons.append(
        {
            "feature": "word_length",
            "a": fa["avg_word_length"],
            "b": fb["avg_word_length"],
            "closeness": feature_diffs["avg_word_length"],
            "note": "Average characters per word.",
        }
    )

    explanation_parts = []
    if tfidf_score >= 0.6:
        explanation_parts.append("Samples share substantial vocabulary and phrasing (high TF-IDF cosine).")
    elif tfidf_score <= 0.2:
        explanation_parts.append("Samples use largely different vocabulary (low TF-IDF cosine).")
    explanation_parts.append(
        f"Lexical style closeness {lexical:.2f} based on sentence length, word length, "
        f"vocabulary diversity and punctuation."
    )

    warnings = []
    if not sufficient:
        warnings.append(
            f"At least {min_words} words per sample are recommended; got "
            f"{fa['word_count']} and {fb['word_count']}. Treat the score as indicative only."
        )
    if identical:
        warnings.append(
            "The samples are identical or near-identical. This may be copied text or a shared "
            "template and is not independent evidence of a shared author."
        )

    details = {
        "tfidf_cosine": round(tfidf_score, 4),
        "feature_similarity": round(feature_score, 4),
        "punctuation_similarity": round(punct_score, 4),
        "lexical_similarity": round(lexical, 4),
        "features_a": fa,
        "features_b": fb,
        "feature_comparison": comparisons,
        "shared_terms": [{"term": term, "weight": weight} for term, weight in shared_terms],
        "sufficient": sufficient,
        "identical_text": identical,
        "warnings": warnings,
        "explanation": " ".join(explanation_parts),
        "note": "Writing-style similarity is analytical support, not proof of identity.",
    }
    return round(float(score), 4), details
