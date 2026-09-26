"""
scanner/scoring.py
===================
The transparent, fixed weighting table for every assessment category,
plus helpers to roll individual CategoryResult objects up into one
overall "Web Security Assessment Score".

IMPORTANT: this score is explicitly NOT a claim that a site is
"X% secure". See websentinel.py's DISCLAIMER text, which is always
printed alongside the score.
"""

CATEGORY_WEIGHTS = {
    "TLS / HTTPS Security": 15,
    "HTTP Security Headers": 15,
    "Cookie Security": 10,
    "CORS": 5,
    "HTTP Methods": 5,
    "Redirect Security": 5,
    "Information Disclosure": 8,
    "DNS Security": 7,
    "Subdomain Security": 5,
    "Technology Detection": 5,
    "API Security": 8,
    "Authentication Security Indicators": 5,
    "Session Security": 4,
    "Content Security": 3,
    "Exposed Files": 3,
    "security.txt": 1,
    "Common Misconfigurations": 4,
    "Safe Service Exposure": 2,
}

# NOTE ON THE NUMBERS BELOW: the individual category weights above are taken
# directly, unmodified, from the specification that requested this tool. Their
# sum is 110, not 100, even though the spec's own table labels the total "100".
# Rather than silently shrinking any individual category's stated weight to
# force the raw numbers to add up, WebSentinel keeps every stated weight
# exactly as given and instead normalizes the *combined* result down to a true
# 0-100 scale in overall_score() below. This keeps each category's relative
# importance faithful to the spec while still making the headline "X/100"
# score mathematically honest.
TOTAL_POSSIBLE = sum(CATEGORY_WEIGHTS.values())  # 110, by construction of the weights above


def overall_score(category_results) -> float:
    """
    Sum each category's weighted_score() (each already 0..its own weight),
    then rescale the total onto a true 0-100 scale using the *actual* sum
    of the weights of the categories provided. Normalizing against the
    categories actually present (rather than the fixed constant above)
    means the headline score is always genuinely out of 100 -- both in a
    full real run (where the weights happen to sum to 110) and in tests
    that exercise a smaller subset of categories.
    """
    raw_total = sum(cat.weighted_score() for cat in category_results)
    total_weight = sum(cat.weight for cat in category_results)
    if total_weight == 0:
        return 0.0
    return round((raw_total / total_weight) * 100, 1)


def grade_for_score(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"
