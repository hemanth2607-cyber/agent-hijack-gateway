"""Fuzz testing with Hypothesis for Normalizer and Detector.

Guarantees:
- Normalizer never raises unhandled exceptions or hangs on arbitrary Unicode inputs.
- Detector never crashes, returns valid risk scores in [0.0, 100.0], and produces valid verdicts.
"""

from hypothesis import given, settings, strategies as st
from app.shield.normalize import normalize_input
from app.shield.detector import Detector
from app.shield.trust import TrustLevel


@settings(max_examples=100, deadline=1000)
@given(st.text())
def test_fuzz_normalize_input(text: str):
    """Normalizer must handle any arbitrary unicode text without crashing."""
    res = normalize_input(text)
    assert isinstance(res.normalized_text, str)
    assert isinstance(res.despaced_text, str)
    assert isinstance(res.obfuscation_signals, list)


@settings(max_examples=50, deadline=1000)
@given(
    text=st.text(min_size=0, max_size=5000),
    trust_level=st.sampled_from([TrustLevel.USER, TrustLevel.EXTERNAL, TrustLevel.SYSTEM]),
)
def test_fuzz_detector_scoring(text: str, trust_level: TrustLevel):
    """Detector must return valid ScanResponse for arbitrary inputs."""
    detector = Detector()
    response = detector.scan_text(text, trust_level=trust_level)
    assert 0.0 <= response.risk_score <= 100.0
    assert response.verdict in ("ALLOW", "FLAG", "BLOCK")
    assert isinstance(response.findings, list)
    assert isinstance(response.reason_codes, list)
    assert response.scan_time_ms >= 0.0
