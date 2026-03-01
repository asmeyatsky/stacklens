from stacklens.domain.models.headers import SecurityHeader
from stacklens.domain.services.header_scoring import score_security_headers


class TestHeaderScoring:
    def test_all_good(self):
        headers = [
            SecurityHeader(name="H1", present=True, value="v", rating="good"),
            SecurityHeader(name="H2", present=True, value="v", rating="good"),
        ]
        assert score_security_headers(headers) == 1.0

    def test_all_missing(self):
        headers = [
            SecurityHeader(name="H1", present=False),
            SecurityHeader(name="H2", present=False),
        ]
        assert score_security_headers(headers) == 0.0

    def test_mixed(self):
        headers = [
            SecurityHeader(name="H1", present=True, value="v", rating="good"),
            SecurityHeader(name="H2", present=False),
        ]
        assert score_security_headers(headers) == 0.5

    def test_empty_list(self):
        assert score_security_headers([]) == 0.0

    def test_warning_rating(self):
        headers = [
            SecurityHeader(name="H1", present=True, value="v", rating="warning"),
        ]
        assert score_security_headers(headers) == 0.5
