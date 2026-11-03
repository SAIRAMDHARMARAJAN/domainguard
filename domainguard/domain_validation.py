"""Network-backed checks used when a company registers a protected domain."""
from __future__ import annotations

import socket


def validate_registered_domain(domain: str) -> None:
    """Require DNS and WHOIS evidence that a protected domain is registered.

    This validates domain infrastructure, not that a domain is harmless. Threat
    safety still comes from watchlist matching, RDAP age, and blocklist data.
    """
    try:
        import dns.resolver
        import whois
    except ImportError as exc:  # pragma: no cover - dependency manifest covers production
        raise RuntimeError("domain validation dependencies are not installed") from exc

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5
    try:
        resolver.resolve(domain, "NS")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout, socket.timeout, OSError) as exc:
        raise ValueError("domain has no resolvable nameservers") from exc

    try:
        record = whois.whois(domain)
    except (OSError, socket.timeout) as exc:
        raise ValueError("domain registration could not be verified") from exc
    if not record or not (record.domain_name or record.creation_date):
        raise ValueError("domain registration could not be verified")
