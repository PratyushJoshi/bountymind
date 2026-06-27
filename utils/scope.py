"""
utils/scope.py
--------------
In-scope URL and hostname filtering.

Strategy (allow important targets, block wasteful third parties):
1. **Allow first** — any hostname matching a scope domain or its subdomains is kept
   (api.target.com, cdn.target.com, staging.target.com, etc.).
2. **Block known third parties** — CDNs, analytics, social, payment, and big-tech domains
   that appear in passive archives but are never in bug-bounty scope.
3. **Strict mode** — everything else is dropped (out-of-scope external links).

Explicit ``scope.domains`` / ``scope.allowlist`` entries always win over the blocklist.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse

from utils.logger import get_logger
from utils.output_helpers import extract_domains_from_url

log = get_logger("scope")

# Known third-party / CDN / analytics / social domains (suffix match).
# In-scope hostnames (target subdomains) are NEVER blocked even if they contain
# similar labels — blocklist only applies to out-of-scope hosts.
THIRD_PARTY_SUFFIXES: FrozenSet[str] = frozenset([
    # Big tech / search / ads
    "google.com", "googleapis.com", "gstatic.com", "googletagmanager.com",
    "google-analytics.com", "googleusercontent.com", "googlesyndication.com",
    "googleadservices.com", "doubleclick.net", "gmail.com", "googlevideo.com",
    "recaptcha.net",
    # Amazon / AWS (URL harvest noise; cloud-bucket module handles S3 separately)
    "amazon.com", "amazonaws.com", "awsstatic.com", "media-amazon.com",
    # Meta / social
    "facebook.com", "fbcdn.net", "instagram.com", "whatsapp.com",
    "twitter.com", "twimg.com", "x.com", "t.co",
    "linkedin.com", "licdn.com", "tiktok.com", "tiktokcdn.com",
    "youtube.com", "youtu.be", "reddit.com", "redd.it", "discord.com",
    "discordapp.com", "pinterest.com", "pinimg.com",
    # Microsoft
    "microsoft.com", "windows.net", "azure.com", "live.com", "office.com",
    "office365.com", "microsoftonline.com", "bing.com",
    # Apple
    "apple.com", "icloud.com", "cdn-apple.com",
    # CDNs & edge networks (external to target unless explicitly scoped)
    "cloudflare.com", "cloudflareinsights.com", "cloudfront.net",
    "fastly.net", "fastlylb.net", "fastly-edge.com",
    "akamai.net", "akamaized.net", "akamaihd.net", "edgekey.net", "edgesuite.net",
    "stackpathdns.com", "kxcdn.com", "keycdn.com", "cdn77.org",
    "jsdelivr.net", "cdn.jsdelivr.net", "unpkg.com", "bootstrapcdn.com",
    "fontawesome.com", "jquery.com", "typekit.net", "fonts.googleapis.com",
    "fonts.gstatic.com",
    # Analytics / marketing / consent
    "hotjar.com", "segment.io", "segment.com", "mixpanel.com", "heap.io",
    "intercom.io", "intercomcdn.com", "optimizely.com", "crazyegg.com",
    "mouseflow.com", "fullstory.com", "clarity.ms", "newrelic.com",
    "cookielaw.org", "onetrust.com", "cookiebot.com", "trustarc.com",
    # Payments / auth SaaS (embedded widgets, not target apps)
    "stripe.com", "paypal.com", "braintreegateway.com",
    "okta.com", "auth0.com", "onelogin.com",
    # Dev / SaaS platforms (noise in archives)
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
    "salesforce.com", "force.com", "hubspot.com", "zendesk.com",
    "shopify.com", "shopifycdn.com", "squarespace.com", "wix.com",
    "wordpress.com", "wp.com", "gravatar.com", "wikipedia.org",
])


@dataclass
class ScopePolicy:
    """Runtime scope rules for a scan session."""

    domains: FrozenSet[str]
    strict: bool = True
    block_third_party: bool = True
    blocklist_extra: FrozenSet[str] = field(default_factory=frozenset)
    allowlist_extra: FrozenSet[str] = field(default_factory=frozenset)

    @classmethod
    def from_session(cls, session) -> "ScopePolicy":
        return cls(
            domains=frozenset(getattr(session, "scope_domains", None) or session.targets or []),
            strict=getattr(session, "scope_strict", True),
            block_third_party=getattr(session, "scope_block_third_party", True),
            blocklist_extra=frozenset(getattr(session, "scope_blocklist_extra", None) or ()),
            allowlist_extra=frozenset(getattr(session, "scope_allowlist_extra", None) or ()),
        )

    @classmethod
    def from_targets(
        cls,
        targets: Sequence[str],
        extra_domains: Optional[Sequence[str]] = None,
        *,
        strict: bool = True,
        block_third_party: bool = True,
        blocklist_extra: Optional[Sequence[str]] = None,
        allowlist_extra: Optional[Sequence[str]] = None,
    ) -> "ScopePolicy":
        domains = build_scope_domains(targets, extra_domains)
        return cls(
            domains=domains,
            strict=strict,
            block_third_party=block_third_party,
            blocklist_extra=frozenset(normalize_scope_domain(d) for d in (blocklist_extra or ()) if d),
            allowlist_extra=frozenset(normalize_scope_domain(d) for d in (allowlist_extra or ()) if d),
        )


@dataclass
class ScopeFilterStats:
    kept: int = 0
    dropped_malformed: int = 0
    dropped_out_of_scope: int = 0
    dropped_third_party: int = 0

    @property
    def dropped_total(self) -> int:
        return self.dropped_malformed + self.dropped_out_of_scope + self.dropped_third_party


def normalize_scope_domain(entry: str) -> str:
    """
    Normalize a target or config scope entry to a bare domain for matching.

    Handles ``example.com``, ``*.example.com``, and ``https://example.com/path``.
    Wildcards strip the ``*.`` prefix so suffix matching applies to all subdomains.
    """
    entry = (entry or "").strip().lower()
    if not entry or entry.startswith("#"):
        return ""
    if entry.startswith(("http://", "https://")):
        return extract_domains_from_url(entry)
    if entry.startswith("*."):
        return entry[2:]
    return entry.lstrip("*.")


def build_scope_domains(
    targets: Sequence[str],
    extra_domains: Optional[Sequence[str]] = None,
) -> FrozenSet[str]:
    """Build the in-scope domain set from CLI targets plus optional config entries."""
    domains: Set[str] = set()
    for raw in list(targets) + list(extra_domains or ()):
        norm = normalize_scope_domain(raw)
        if norm:
            domains.add(norm)
    return frozenset(domains)


def extract_hostname(url: str) -> Optional[str]:
    """Extract lowercase hostname from a URL; return None for malformed input."""
    if not url or not isinstance(url, str):
        return None
    candidate = url.strip()
    if not candidate:
        return None
    try:
        if "://" not in candidate:
            candidate = "http://" + candidate.lstrip("/")
        parsed = urlparse(candidate)
        host = parsed.hostname
        if host:
            return host.lower()
        netloc = parsed.netloc.split("@")[-1]
        host = netloc.split(":")[0].lower()
        return host or None
    except Exception:
        return None


def hostname_in_scope(hostname: str, domains: Set[str] | FrozenSet[str]) -> bool:
    """
    True when *hostname* equals a scope domain or is its subdomain.

    Keeps all important target assets: ``api.``, ``cdn.``, ``staging.``, etc.
    """
    host = (hostname or "").strip().lower().rstrip(".")
    if not host or not domains:
        return False
    for domain in domains:
        base = normalize_scope_domain(domain)
        if not base:
            continue
        if host == base or host.endswith("." + base):
            return True
    return False


def is_known_third_party(
    hostname: str,
    *,
    blocklist_extra: FrozenSet[str] = frozenset(),
    allowlist_extra: FrozenSet[str] = frozenset(),
) -> bool:
    """
    True when hostname matches a known CDN / analytics / big-tech suffix.

    ``allowlist_extra`` overrides the blocklist (force-keep related assets).
    """
    host = (hostname or "").strip().lower().rstrip(".")
    if not host:
        return False

    for allowed in allowlist_extra:
        base = normalize_scope_domain(allowed)
        if base and (host == base or host.endswith("." + base)):
            return False

    all_suffixes = THIRD_PARTY_SUFFIXES | blocklist_extra
    for suffix in all_suffixes:
        suffix = suffix.lower().strip()
        if host == suffix or host.endswith("." + suffix):
            return True
    return False


def url_is_allowed(url: str, policy: ScopePolicy) -> bool:
    """
    Decide whether a URL should be scanned.

    Order: malformed → deny | in-scope → allow | third-party block → deny |
    strict out-of-scope → deny | else allow (non-strict legacy).
    """
    host = extract_hostname(url)
    if not host:
        return False

    # In-scope hostnames always win — never drop target subdomains/CDN aliases.
    if hostname_in_scope(host, policy.domains):
        return True

    # Explicit allowlist — keep related third-party assets (e.g. a CloudFront distro).
    for allowed in policy.allowlist_extra:
        base = normalize_scope_domain(allowed)
        if base and (host == base or host.endswith("." + base)):
            return True

    if policy.block_third_party and is_known_third_party(
        host,
        blocklist_extra=policy.blocklist_extra,
        allowlist_extra=policy.allowlist_extra,
    ):
        return False

    if policy.strict:
        return False

    return True


def hostname_is_allowed(hostname: str, policy: ScopePolicy) -> bool:
    """Like ``url_is_allowed`` but for bare hostnames."""
    host = (hostname or "").strip().lower().rstrip(".")
    if not host:
        return False
    if hostname_in_scope(host, policy.domains):
        return True

    for allowed in policy.allowlist_extra:
        base = normalize_scope_domain(allowed)
        if base and (host == base or host.endswith("." + base)):
            return True

    if policy.block_third_party and is_known_third_party(
        host,
        blocklist_extra=policy.blocklist_extra,
        allowlist_extra=policy.allowlist_extra,
    ):
        return False
    return not policy.strict


def filter_in_scope(
    urls: List[str],
    domains: Set[str] | FrozenSet[str],
    *,
    strict: bool = True,
    block_third_party: bool = True,
    blocklist_extra: Optional[Sequence[str]] = None,
    allowlist_extra: Optional[Sequence[str]] = None,
) -> List[str]:
    """
    Keep URLs that pass scope policy. Malformed URLs are dropped.

    Backward-compatible wrapper around ``filter_urls``.
    """
    policy = ScopePolicy(
        domains=frozenset(domains),
        strict=strict,
        block_third_party=block_third_party,
        blocklist_extra=frozenset(
            normalize_scope_domain(d) for d in (blocklist_extra or ()) if d
        ),
        allowlist_extra=frozenset(
            normalize_scope_domain(d) for d in (allowlist_extra or ()) if d
        ),
    )
    filtered, _ = filter_urls(urls, policy)
    return filtered


def filter_urls(urls: List[str], policy: ScopePolicy) -> Tuple[List[str], ScopeFilterStats]:
    """Filter URLs; return kept list and detailed drop statistics."""
    stats = ScopeFilterStats()
    if not policy.domains and policy.strict:
        return list(urls), stats

    kept: List[str] = []
    seen: Set[str] = set()

    for url in urls:
        if not url or not isinstance(url, str):
            stats.dropped_malformed += 1
            continue
        url = url.strip()
        host = extract_hostname(url)
        if not host:
            stats.dropped_malformed += 1
            continue

        if hostname_in_scope(host, policy.domains):
            if url not in seen:
                seen.add(url)
                kept.append(url)
            stats.kept += 1
            continue

        for allowed in policy.allowlist_extra:
            base = normalize_scope_domain(allowed)
            if base and (host == base or host.endswith("." + base)):
                if url not in seen:
                    seen.add(url)
                    kept.append(url)
                stats.kept += 1
                continue

        if policy.block_third_party and is_known_third_party(
            host,
            blocklist_extra=policy.blocklist_extra,
            allowlist_extra=policy.allowlist_extra,
        ):
            stats.dropped_third_party += 1
            log.debug("Third-party blocked: %s", url[:120])
            continue

        if policy.strict:
            stats.dropped_out_of_scope += 1
            log.debug("Out of scope: %s", url[:120])
            continue

        if url not in seen:
            seen.add(url)
            kept.append(url)
        stats.kept += 1

    if stats.dropped_total:
        log.info(
            "Scope filter: kept %d | dropped %d (third-party=%d, out-of-scope=%d, malformed=%d)",
            len(kept),
            stats.dropped_total,
            stats.dropped_third_party,
            stats.dropped_out_of_scope,
            stats.dropped_malformed,
        )
    return kept, stats


def filter_url_mapping(
    mapping: dict,
    policy: ScopePolicy,
) -> Tuple[dict, ScopeFilterStats]:
    """Filter a url→metadata dict."""
    stats = ScopeFilterStats()
    kept: dict = {}
    for url, meta in mapping.items():
        if url_is_allowed(url, policy):
            kept[url] = meta
            stats.kept += 1
        else:
            host = extract_hostname(url)
            if not host:
                stats.dropped_malformed += 1
            elif is_known_third_party(host, blocklist_extra=policy.blocklist_extra):
                stats.dropped_third_party += 1
            else:
                stats.dropped_out_of_scope += 1
    return kept, stats


def apply_scope_to_session(session, strict: bool = True) -> int:
    """
    Filter all URL-bearing collections on a ScanSession in-place.

    Returns the total number of items removed.
    """
    policy = ScopePolicy.from_session(session)
    if not policy.strict and not policy.block_third_party:
        return 0
    if not policy.domains and policy.strict:
        return 0

    removed = 0

    before = len(session.subdomains)
    session.subdomains = [
        s for s in session.subdomains
        if hostname_is_allowed(s.domain, policy)
    ]
    removed += before - len(session.subdomains)

    before = len(session.live_hosts)
    session.live_hosts = [
        h for h in session.live_hosts
        if url_is_allowed(h.url, policy)
    ]
    removed += before - len(session.live_hosts)

    before = len(session.directory_findings)
    session.directory_findings = [
        d for d in session.directory_findings
        if url_is_allowed(d.url, policy)
    ]
    removed += before - len(session.directory_findings)

    before = len(session.harvested_urls)
    session.harvested_urls = [
        u for u in session.harvested_urls
        if url_is_allowed(u.url, policy)
    ]
    removed += before - len(session.harvested_urls)

    if session.waf_detections:
        before = len(session.waf_detections)
        session.waf_detections = {
            url: name for url, name in session.waf_detections.items()
            if url_is_allowed(url, policy)
        }
        removed += before - len(session.waf_detections)

    if removed:
        log.info("Scope enforcement removed %d out-of-scope / third-party item(s)", removed)
        session.scope_filtered_count = getattr(session, "scope_filtered_count", 0) + removed

    return removed


def format_scope_drop_message(stats: ScopeFilterStats) -> str:
    """Human-readable summary for console output."""
    parts = []
    if stats.dropped_third_party:
        parts.append(f"{stats.dropped_third_party} third-party/CDN")
    if stats.dropped_out_of_scope:
        parts.append(f"{stats.dropped_out_of_scope} out-of-scope")
    if stats.dropped_malformed:
        parts.append(f"{stats.dropped_malformed} malformed")
    if not parts:
        return ""
    return f"Scope filter removed {' + '.join(parts)} URL(s); kept {stats.kept} in-scope"
