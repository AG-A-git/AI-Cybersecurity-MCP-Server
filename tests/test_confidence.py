from scanner.confidence import calculate_confidence


def test_direct_source_confidence():
    confidence = calculate_confidence(
        direct_source=True
    )

    assert confidence == 95


def test_tracked_source_confidence():
    confidence = calculate_confidence(
        tracked_source=True
    )

    assert confidence == 90


def test_ambiguous_source_confidence():
    confidence = calculate_confidence()

    assert confidence == 70


def test_validated_source_confidence():
    confidence = calculate_confidence(
        tracked_source=True,
        validated=True
    )

    assert confidence == 70


def test_confidence_range():
    confidence = calculate_confidence(
        direct_source=True
    )

    assert 0 <= confidence <= 100
