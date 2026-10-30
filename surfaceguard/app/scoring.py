"""Turn findings into a 0-100 score and an A-F grade."""

WEIGHTS = {"critical": 25, "high": 12, "medium": 6, "low": 2, "info": 0}
GRADES = [(90, "A"), (80, "B"), (70, "C"), (55, "D"), (0, "F")]


def score_findings(findings):
    score = max(0, 100 - sum(WEIGHTS[f["severity"]] for f in findings))
    # A single critical issue caps the grade, no matter how clean the rest is.
    if any(f["severity"] == "critical" for f in findings):
        score = min(score, 54)
    grade = next(g for threshold, g in GRADES if score >= threshold)
    return score, grade


def severity_counts(findings):
    counts = {k: 0 for k in WEIGHTS}
    for f in findings:
        counts[f["severity"]] += 1
    return counts


def diff_findings(old, new):
    """Findings present in `new` but not in `old` (used for alerts).

    Findings match on their stable `id` (titles may contain changing numbers, such as days
    until certificate expiry). Results stored before ids existed have no `id`, so a finding
    also counts as already seen when an old one has the same (check, title)."""
    seen_ids = {f["id"] for f in old if f.get("id")}
    seen_titles = {(f["check"], f["title"]) for f in old}

    def is_new(f):
        if f.get("id") and f["id"] in seen_ids:
            return False
        return (f["check"], f["title"]) not in seen_titles
    return [f for f in new if f["severity"] != "info" and is_new(f)]
