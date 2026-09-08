"""Outbound network guard and SSRF prevention engine for AegisAgent V2.

Enforces zero-trust outbound network controls, domain whitelisting/blacklisting,
strict DNS resolution inspection, cloud metadata protection, and HTTP method/egress restraints.
"""

import ipaddress
import logging
import socket
import urllib.parse
from typing import Optional, Set, Tuple

logger = logging.getLogger(__name__)


class OutboundNetworkGuard:
    """Zero-trust outbound network guard preventing SSRF, private network sweep, and illegal data egress."""

    ALLOWED_SCHEMES = {"http", "https"}
    DEFAULT_MAX_PAYLOAD_BYTES = 32768  # 32 KB egress payload limit

    # Known malicious or testing attacker domains blocked by default
    DEFAULT_BLOCKED_DOMAINS: Set[str] = {
        "evil.com",
        "attacker.com",
        "malicious.org",
        "leak.sh",
        "exfil.net",
        "webhook.site",
    }

    # Internal hostnames and TLDs blocked from agent egress
    BLOCKED_HOST_SUFFIXES: Set[str] = {
        ".internal",
        ".local",
        ".localhost",
        ".lan",
        ".corp",
        ".intranet",
        ".home",
    }

    def __init__(
        self,
        allowed_domains: Optional[Set[str]] = None,
        blocked_domains: Optional[Set[str]] = None,
        max_payload_bytes: int = DEFAULT_MAX_PAYLOAD_BYTES,
        strict_dns: bool = False,
    ) -> None:
        """Initialize OutboundNetworkGuard with domain controls and payload policies.

        Args:
            allowed_domains: Optional explicit whitelist of permitted outbound domains.
            blocked_domains: Optional custom blacklist of prohibited outbound domains.
            max_payload_bytes: Maximum permitted outbound payload size in bytes.
            strict_dns: If True, require successful DNS resolution for all domain names.
        """
        self.allowed_domains = set(allowed_domains) if allowed_domains else set()
        self.blocked_domains = set(self.DEFAULT_BLOCKED_DOMAINS)
        if blocked_domains:
            self.blocked_domains.update(blocked_domains)
        self.max_payload_bytes = max_payload_bytes
        self.strict_dns = strict_dns

    def _is_private_or_reserved_ip(self, ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Tuple[bool, str]:
        """Check if an IP address belongs to loopback, private, link-local, cloud metadata, or reserved ranges."""
        # 1. Loopback check (127.0.0.0/8, ::1)
        if ip_obj.is_loopback:
            return True, f"Loopback address ({ip_obj})"

        # 2. Private RFC-1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
        if ip_obj.is_private:
            return True, f"Private RFC-1918 address ({ip_obj})"

        # 3. Link-Local & Cloud Metadata (169.254.0.0/16, fe80::/10, AWS/GCP/Azure 169.254.169.254, Alibaba 100.100.100.100)
        if ip_obj.is_link_local:
            return True, f"Link-Local / Cloud Metadata address ({ip_obj})"

        str_ip = str(ip_obj)
        if str_ip in {"169.254.169.254", "169.254.170.2", "100.100.100.100"}:
            return True, f"Cloud Instance Metadata Service endpoint ({ip_obj})"

        # Handle IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1)
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
            return self._is_private_or_reserved_ip(ip_obj.ipv4_mapped)

        # 4. Multicast, Reserved, Unspecified (0.0.0.0/8, 224.0.0.0/4, 240.0.0.0/4)
        if ip_obj.is_multicast:
            return True, f"Multicast address ({ip_obj})"

        if ip_obj.is_reserved:
            return True, f"Reserved address ({ip_obj})"

        if ip_obj.is_unspecified:
            return True, f"Unspecified address ({ip_obj})"

        # Additional IPv4 checks for 0.0.0.0/8 or 240.0.0.0/4
        if isinstance(ip_obj, ipaddress.IPv4Address):
            octets = ip_obj.exploded.split(".")
            first_octet = int(octets[0])
            if first_octet == 0 or first_octet >= 240:
                return True, f"Reserved IPv4 block ({ip_obj})"

        return False, "Public IP"

    def validate_url(self, url: str) -> Tuple[bool, str]:
        """Validate destination URL against SSRF, private subnet routing, and domain policies.

        Args:
            url: Destination URL string to validate.

        Returns:
            Tuple of (is_valid: bool, reason: str).
        """
        if not url or not isinstance(url, str):
            return False, "Invalid or empty URL parameter"

        url_str = url.strip()

        # Parse URL
        try:
            parsed = urllib.parse.urlparse(url_str)
        except Exception as e:
            return False, f"URL parse failure: {e}"

        # 1. Scheme Validation
        if parsed.scheme.lower() not in self.ALLOWED_SCHEMES:
            return False, f"Blocked scheme '{parsed.scheme}': only http and https are permitted."

        hostname = parsed.hostname
        if not hostname:
            return False, "URL missing valid hostname or IP address"

        hostname_lower = hostname.lower().strip().strip("[]")

        # 2. Localhost, Cloud Metadata Domains, & Suffix Check
        if hostname_lower in {
            "localhost", "127.0.0.1", "::1", "0.0.0.0",
            "metadata.google.internal", "metadata", "kubernetes.default", "kubernetes.default.svc"
        }:
            return False, f"Blocked SSRF attempt to internal host '{hostname}'"

        for suffix in self.BLOCKED_HOST_SUFFIXES:
            if hostname_lower.endswith(suffix):
                return False, f"Blocked SSRF attempt to internal network suffix '{suffix}'"

        # 3. Direct / Encoded IP Address Inspection (including integer/decimal IP encodings)
        try:
            if hostname_lower.isdigit():
                int_ip = int(hostname_lower)
                if 0 <= int_ip <= 0xFFFFFFFF:
                    ip_obj = ipaddress.IPv4Address(int_ip)
                    is_blocked, ip_reason = self._is_private_or_reserved_ip(ip_obj)
                    if is_blocked:
                        return False, f"Blocked SSRF attempt to {ip_reason} (encoded decimal IP)"
            else:
                ip_obj = ipaddress.ip_address(hostname_lower)
                is_blocked, ip_reason = self._is_private_or_reserved_ip(ip_obj)
                if is_blocked:
                    return False, f"Blocked SSRF attempt to {ip_reason}"
        except ValueError:
            # Hostname is a domain name, not a raw IP literal
            pass

        # 4. Domain Blacklist Check
        if hostname_lower in self.blocked_domains or any(
            hostname_lower.endswith("." + b) for b in self.blocked_domains
        ):
            return False, f"Blocked outbound destination: domain '{hostname}' is blacklisted."

        # 5. Domain Whitelist Check (if configured)
        if self.allowed_domains:
            is_allowed = hostname_lower in self.allowed_domains or any(
                hostname_lower.endswith("." + a) for a in self.allowed_domains
            )
            if not is_allowed:
                return False, f"Blocked outbound destination: domain '{hostname}' is not in allowed_domains."

        # 6. DNS Resolution & Rebinding Protection
        try:
            addr_info = socket.getaddrinfo(hostname_lower, None)
            for item in addr_info:
                sockaddr = item[4]
                resolved_ip_str = sockaddr[0]
                try:
                    resolved_ip_obj = ipaddress.ip_address(resolved_ip_str)
                    is_blocked, ip_reason = self._is_private_or_reserved_ip(resolved_ip_obj)
                    if is_blocked:
                        return False, f"Blocked SSRF attempt to {ip_reason} resolved from host '{hostname}'"
                except ValueError:
                    continue
        except (socket.gaierror, socket.herror, OSError) as e:
            if self.strict_dns:
                return False, f"DNS resolution failed for host '{hostname}': {e}"
            logger.debug("DNS lookup skipped or failed for '%s': %s", hostname, e)

        return True, "URL and destination host validated successfully."

    def validate_request(
        self,
        method: str = "GET",
        payload_size_bytes: int = 0,
        is_tainted: bool = False,
    ) -> Tuple[bool, str]:
        """Validate HTTP method and outbound payload size under session taint state.

        Args:
            method: HTTP method (e.g., GET, POST, PUT, DELETE).
            payload_size_bytes: Size of outbound body in bytes.
            is_tainted: True if session contains untrusted external inputs.

        Returns:
            Tuple of (is_valid: bool, reason: str).
        """
        method_upper = method.upper().strip()

        # In tainted sessions, restrict to read-only HTTP methods
        if is_tainted and method_upper not in {"GET", "HEAD", "OPTIONS"}:
            return False, f"HTTP method '{method_upper}' prohibited in tainted session (read-only GET/HEAD allowed)."

        # Check payload size limit
        if payload_size_bytes > self.max_payload_bytes:
            return False, (
                f"Outbound payload size ({payload_size_bytes} bytes) exceeds "
                f"maximum threshold ({self.max_payload_bytes} bytes)."
            )

        return True, "Request parameters permitted."
