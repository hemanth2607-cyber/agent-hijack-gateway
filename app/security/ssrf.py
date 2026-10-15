"""Server-Side Request Forgery (SSRF) validation and defense.

Protects against:
- RFC 1918 Private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Loopback addresses (127.0.0.0/8, ::1)
- Cloud instance metadata services (169.254.169.254, 169.254.0.0/16)
- Alternative IP formats: decimal, octal, hexadecimal, zero-compressed notation
- Non-HTTP schemes (file://, gopher://, dict://, ftp://)
- DNS rebinding & malicious redirection
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.parse
from typing import List, Optional, Tuple


FORBIDDEN_SCHEMES = {"file", "gopher", "dict", "ftp", "ldap", "tftp", "data", "blob", "javascript"}

# IP Networks that must NEVER be contacted by the agent
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (only valid as source address)
    ipaddress.ip_network("10.0.0.0/8"),          # RFC 1918 Private
    ipaddress.ip_network("100.64.0.0/10"),       # Carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),      # Link-local / Cloud metadata
    ipaddress.ip_network("172.16.0.0/12"),       # RFC 1918 Private
    ipaddress.ip_network("192.0.0.0/24"),        # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),        # TEST-NET-1
    ipaddress.ip_network("192.88.99.0/24"),      # 6to4 Relay Anycast
    ipaddress.ip_network("192.168.0.0/16"),      # RFC 1918 Private
    ipaddress.ip_network("198.18.0.0/15"),       # Network Interconnect Device Benchmark
    ipaddress.ip_network("198.51.100.0/24"),     # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),      # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved for future use
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6 Blocked
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("fc00::/7"),           # Unique local
    ipaddress.ip_network("fe80::/10"),          # Link-local unicast
    ipaddress.ip_network("ff00::/8"),           # Multicast
]


def is_ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Tuple[bool, Optional[str]]:
    """Checks if an IP object falls into any blocked or private range."""
    # Handle IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    if ip.is_loopback:
        return True, "BLOCKED_LOOPBACK_ADDRESS"
    if ip.is_link_local:
        return True, "BLOCKED_LINK_LOCAL_METADATA"
    if ip.is_private:
        return True, "BLOCKED_PRIVATE_NETWORK"
    if ip.is_multicast:
        return True, "BLOCKED_MULTICAST_ADDRESS"
    if ip.is_reserved:
        return True, "BLOCKED_RESERVED_ADDRESS"

    for blocked_net in BLOCKED_NETWORKS:
        if ip in blocked_net:
            return True, f"BLOCKED_NETWORK_RANGE_{blocked_net}"

    return False, None


def parse_and_validate_ip(host: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Attempts to parse host string as IPv4 or IPv6, handling alternative representations."""
    # Direct standard parsing
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass

    # Decimal or single-number octal integer format (e.g., 2130706433, 017700000001)
    if host.isdigit():
        try:
            if host.startswith("0") and len(host) > 1:
                val = int(host, 8)
            else:
                val = int(host, 10)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except ValueError:
            pass

    # Hexadecimal format (e.g., 0x7f000001)
    if host.lower().startswith("0x"):
        try:
            val = int(host, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except ValueError:
            pass

    # Octal or mixed dotted notation (e.g., 0177.0.0.1)
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() or p.lower().startswith("0x") for p in parts):
        try:
            int_parts = []
            for p in parts:
                if p.lower().startswith("0x"):
                    int_parts.append(int(p, 16))
                elif p.startswith("0") and len(p) > 1 and p.isdigit():
                    int_parts.append(int(p, 8))
                else:
                    int_parts.append(int(p, 10))
            if all(0 <= p <= 255 for p in int_parts):
                ip_int = (int_parts[0] << 24) + (int_parts[1] << 16) + (int_parts[2] << 8) + int_parts[3]
                return ipaddress.IPv4Address(ip_int)
        except ValueError:
            pass

    return None


def validate_url(
    url_str: str,
    allowed_domains: Optional[List[str]] = None,
    resolve_dns: bool = True,
) -> Tuple[bool, str]:
    """Validates target URL against SSRF vulnerabilities and domain allowlists.

    Returns:
        (is_safe: bool, reason_code: str)
    """
    if not url_str or not isinstance(url_str, str):
        return False, "INVALID_URL_EMPTY"

    try:
        parsed = urllib.parse.urlsplit(url_str)
    except Exception:
        return False, "INVALID_URL_SYNTAX"

    scheme = parsed.scheme.lower()
    if scheme in FORBIDDEN_SCHEMES or scheme not in ("http", "https"):
        return False, f"FORBIDDEN_URL_SCHEME_{scheme.upper()}"

    hostname = parsed.hostname
    if not hostname:
        return False, "INVALID_URL_MISSING_HOST"

    # Strip surrounding brackets for IPv6
    clean_host = hostname.strip("[]").lower()

    # 1. Test for direct IP address representation
    direct_ip = parse_and_validate_ip(clean_host)
    if direct_ip is not None:
        blocked, reason = is_ip_blocked(direct_ip)
        if blocked:
            return False, reason or "BLOCKED_IP_ADDRESS"

    # 2. Check domain allowlist if configured
    if allowed_domains:
        domain_matched = False
        for allowed in allowed_domains:
            allowed = allowed.lower()
            if clean_host == allowed or clean_host.endswith(f".{allowed}"):
                domain_matched = True
                break
        if not domain_matched:
            return False, f"DOMAIN_NOT_IN_ALLOWLIST_{clean_host}"

    # 3. DNS Resolution Guard (prevents DNS rebinding and private host resolution)
    if resolve_dns and direct_ip is None:
        try:
            # Resolve both IPv4 and IPv6 addresses
            addr_info = socket.getaddrinfo(clean_host, parsed.port or (443 if scheme == "https" else 80))
            for family, _, _, _, sockaddr in addr_info:
                resolved_ip_str = sockaddr[0]
                resolved_ip = ipaddress.ip_address(resolved_ip_str)
                blocked, reason = is_ip_blocked(resolved_ip)
                if blocked:
                    return False, f"DNS_RESOLVED_TO_{reason}"
        except socket.gaierror:
            # In fail-closed security gateway, unresolvable domains cannot be safely verified
            return False, "DNS_RESOLUTION_FAILED"
        except Exception:
            return False, "DNS_LOOKUP_ERROR"

    return True, "URL_VALIDATED_SAFE"


def validate_and_pin_url(
    url_str: str,
    allowed_domains: Optional[List[str]] = None,
) -> Tuple[bool, str, Optional[str], Optional[int]]:
    """Validates URL and resolves safe IP address to pin connection against DNS rebinding.

    Returns:
        (is_safe: bool, reason_code: str, pinned_ip: Optional[str], port: Optional[int])
    """
    if not url_str or not isinstance(url_str, str):
        return False, "INVALID_URL_EMPTY", None, None

    try:
        parsed = urllib.parse.urlsplit(url_str)
    except Exception:
        return False, "INVALID_URL_SYNTAX", None, None

    scheme = parsed.scheme.lower()
    if scheme in FORBIDDEN_SCHEMES or scheme not in ("http", "https"):
        return False, f"FORBIDDEN_URL_SCHEME_{scheme.upper()}", None, None

    hostname = parsed.hostname
    if not hostname:
        return False, "INVALID_URL_MISSING_HOST", None, None

    port = parsed.port or (443 if scheme == "https" else 80)
    clean_host = hostname.strip("[]").lower()

    # 1. Direct IP check
    direct_ip = parse_and_validate_ip(clean_host)
    if direct_ip is not None:
        blocked, reason = is_ip_blocked(direct_ip)
        if blocked:
            return False, reason or "BLOCKED_IP_ADDRESS", None, None
        return True, "URL_VALIDATED_SAFE", str(direct_ip), port

    # 2. Domain Allowlist Check
    if allowed_domains:
        domain_matched = any(
            clean_host == allowed.lower() or clean_host.endswith(f".{allowed.lower()}")
            for allowed in allowed_domains
        )
        if not domain_matched:
            return False, f"DOMAIN_NOT_IN_ALLOWLIST_{clean_host}", None, None

    # 3. DNS Resolution & IP Pinning
    try:
        addr_info = socket.getaddrinfo(clean_host, port)
        first_safe_ip: Optional[str] = None
        for family, _, _, _, sockaddr in addr_info:
            resolved_ip_str = sockaddr[0]
            resolved_ip = ipaddress.ip_address(resolved_ip_str)
            blocked, reason = is_ip_blocked(resolved_ip)
            if blocked:
                return False, f"DNS_RESOLVED_TO_{reason}", None, None
            if first_safe_ip is None:
                first_safe_ip = resolved_ip_str

        if not first_safe_ip:
            return False, "DNS_RESOLUTION_NO_IP", None, None

        return True, "URL_VALIDATED_SAFE", first_safe_ip, port
    except socket.gaierror:
        return False, "DNS_RESOLUTION_FAILED", None, None
    except Exception:
        return False, "DNS_LOOKUP_ERROR", None, None


def build_pinned_http_request(url_str: str, pinned_ip: str, port: int) -> dict:
    """Constructs HTTP request parameters pinning the verified IP.

    Ensures the client socket connects directly to the validated IP,
    completely preventing DNS Rebinding attacks.
    """
    parsed = urllib.parse.urlsplit(url_str)
    scheme = parsed.scheme.lower()
    host_header = (
        f"{parsed.hostname}:{port}"
        if (scheme == "http" and port != 80) or (scheme == "https" and port != 443)
        else parsed.hostname
    )
    pinned_url = f"{scheme}://{pinned_ip}:{port}{parsed.path or '/'}"
    if parsed.query:
        pinned_url += f"?{parsed.query}"

    return {
        "pinned_url": pinned_url,
        "headers": {"Host": host_header or ""},
        "original_host": parsed.hostname,
        "pinned_ip": pinned_ip,
        "port": port,
    }
