from scanner.models import CategoryResult, Finding
from scanner.scoring import CATEGORY_WEIGHTS, TOTAL_POSSIBLE, grade_for_score, overall_score


def test_category_weights_match_spec_and_total_possible():
    # The individual weights are preserved exactly as specified (they
    # happen to sum to 110, not the 100 the spec's own table claims --
    # see the note in scanner/scoring.py). TOTAL_POSSIBLE always reflects
    # whatever the weights actually sum to; overall_score() is what
    # guarantees the final reported score is genuinely out of 100.
    assert TOTAL_POSSIBLE == sum(CATEGORY_WEIGHTS.values())
    assert CATEGORY_WEIGHTS["TLS / HTTPS Security"] == 15
    assert CATEGORY_WEIGHTS["HTTP Security Headers"] == 15
    assert CATEGORY_WEIGHTS["security.txt"] == 1


def test_overall_score_is_always_out_of_100_regardless_of_weight_sum():
    # Even though the real weight table sums to 110, a full-weight run
    # must still report a score capped at 100.
    cats = [CategoryResult(category=name, weight=w) for name, w in CATEGORY_WEIGHTS.items()]
    score = overall_score(cats)  # every category empty -> perfect score
    assert score == 100.0


def test_empty_category_scores_full_weight():
    cat = CategoryResult(category="Test", weight=10)
    assert cat.sub_score() == 100
    assert cat.weighted_score() == 10


def test_failed_high_severity_deducts_points():
    cat = CategoryResult(category="Test", weight=10)
    cat.add(Finding("a", "A", passed=False, severity="HIGH", description="x"))
    assert cat.sub_score() == 75
    assert cat.weighted_score() == 7.5


def test_score_floors_at_zero():
    cat = CategoryResult(category="Test", weight=10)
    for i in range(10):
        cat.add(Finding(f"f{i}", f"F{i}", passed=False, severity="CRITICAL", description="x"))
    assert cat.sub_score() == 0
    assert cat.weighted_score() == 0


def test_skipped_category_scores_zero():
    cat = CategoryResult(category="Test", weight=10, skipped_reason="dependency missing")
    assert cat.sub_score() == 0
    assert cat.weighted_score() == 0


def test_overall_score_sums_weighted_scores():
    cat1 = CategoryResult(category="A", weight=50)  # empty -> full 50
    cat2 = CategoryResult(category="B", weight=50)
    cat2.add(Finding("x", "X", passed=False, severity="MEDIUM", description="x"))  # 88/100 * 50 = 44
    score = overall_score([cat1, cat2])
    assert score == 94.0


def test_grade_boundaries():
    assert grade_for_score(95) == "A"
    assert grade_for_score(90) == "A"
    assert grade_for_score(89.9) == "B"
    assert grade_for_score(70) == "C"
    assert grade_for_score(60) == "D"
    assert grade_for_score(59.9) == "F"
    assert grade_for_score(0) == "F"


def test_info_severity_never_deducts():
    cat = CategoryResult(category="Test", weight=10)
    cat.add(Finding("a", "A", passed=False, severity="INFO", description="x"))
    assert cat.sub_score() == 100
