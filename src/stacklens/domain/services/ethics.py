from __future__ import annotations

from stacklens.domain.ports.http_client import HttpClientPort


class EthicsViolation(Exception):
    pass


class EthicsPolicy:
    """Simplified robots.txt checker for ethical scanning."""

    def __init__(self, http_client: HttpClientPort) -> None:
        self._http = http_client

    async def check_robots_txt(self, base_url: str, *, strict: bool = False) -> bool:
        """Return True if scanning is allowed. In strict mode, raise on disallow."""
        try:
            resp = await self._http.get(f"{base_url}/robots.txt", follow_redirects=True)
            if resp.status_code != 200:
                return True
            disallowed = self._is_disallowed(resp.text)
            if disallowed and strict:
                raise EthicsViolation(
                    f"robots.txt at {base_url} disallows our user-agent"
                )
            return not disallowed
        except EthicsViolation:
            raise
        except Exception:
            return True

    @staticmethod
    def _is_disallowed(robots_txt: str) -> bool:
        in_our_block = False
        in_wildcard_block = False
        for line in robots_txt.splitlines():
            line = line.split("#", 1)[0].strip().lower()
            if line.startswith("user-agent:"):
                agent = line.split(":", 1)[1].strip()
                in_our_block = agent == "stacklens"
                in_wildcard_block = agent == "*"
            elif line.startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path == "/" and (in_our_block or in_wildcard_block):
                    return True
        return False
