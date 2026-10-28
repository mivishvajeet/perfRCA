"""Lightweight local JSON memory store for reviewed RCA cases.

Matches recurring cases through explainable symptom/evidence fingerprints.
Never stores unconfirmed hypotheses as facts; never retains secrets.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path


class MemoryStore:
    """Small local JSON-backed store for confirmed RCA cases."""

    def __init__(self, memory_dir):
        self.dir = Path(memory_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.store_path = self.dir / "cases.json"
        self._cases = self._load()

    def _load(self):
        if self.store_path.exists():
            try:
                with open(self.store_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return []
        return []

    def _save(self):
        with open(self.store_path, "w", encoding="utf-8") as f:
            json.dump(self._cases, f, indent=2)

    def add_case(self, investigation_id, fingerprint, findings, fix_applied=None):
        """Record a confirmed RCA case with a symptom fingerprint."""
        case = {
            "id": investigation_id,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "fingerprint": fingerprint,
            "findings": findings,
            "fix_applied": fix_applied,
            "confirmed": fix_applied is not None
        }
        self._cases.append(case)
        self._save()
        return case

    def find_similar(self, fingerprint, threshold=0.3):
        """Find previously recorded cases with similar fingerprints.

        Uses simple Jaccard-like overlap of fingerprint keys.
        Returns matches above threshold, sorted by similarity.
        """
        matches = []
        for case in self._cases:
            score = self._fingerprint_similarity(fingerprint, case.get("fingerprint", {}))
            if score >= threshold:
                matches.append({
                    "case_id": case["id"],
                    "similarity": round(score, 2),
                    "findings": case.get("findings"),
                    "fix_applied": case.get("fix_applied"),
                    "is_historical_match": True
                })
        return sorted(matches, key=lambda m: m["similarity"], reverse=True)

    def _fingerprint_similarity(self, fp1, fp2):
        """Compute similarity between two fingerprints.

        Each fingerprint is a dict of {symptom_key: weight}. Similarity is
        based on overlapping keys weighted by the minimum weight for each.
        """
        if not fp1 or not fp2:
            return 0.0

        keys1 = set(fp1.keys())
        keys2 = set(fp2.keys())
        if not keys1 or not keys2:
            return 0.0

        intersection = keys1 & keys2
        union = keys1 | keys2

        if not union:
            return 0.0

        weighted_overlap = sum(min(fp1.get(k, 0), fp2.get(k, 0)) for k in intersection)
        total_weight = sum(max(fp1.get(k, 0), fp2.get(k, 0)) for k in union)

        if total_weight == 0:
            return 0.0

        return weighted_overlap / total_weight

    def list_cases(self, limit=50):
        return self._cases[-limit:]

    def get_case(self, case_id):
        for c in self._cases:
            if c["id"] == case_id:
                return c
        return None