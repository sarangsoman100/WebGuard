import socket
import ssl
from urllib.parse import urlparse

import requests


def check_transport_security(url):
    """
    Check basic HTTP/HTTPS transport security.

    This detector:
    - identifies plain HTTP
    - checks whether HTTP redirects to HTTPS
    - checks HTTPS certificate validity
    - reports certificate/hostname problems

    It intentionally does not perform aggressive TLS scanning.
    """

    findings = []

    parsed = urlparse(url)

    if not parsed.scheme or not parsed.netloc:
        return findings

    hostname = parsed.hostname

    if not hostname:
        return findings

    # ========================================================
    # HTTP
    # ========================================================

    if parsed.scheme.lower() == "http":

        try:

            response = requests.get(
                url,
                timeout=5,
                allow_redirects=False,
            )

            location = response.headers.get(
                "Location",
                "",
            )

            if location.lower().startswith(
                "https://"
            ):

                findings.append({
                    "type": "Transport Security",
                    "category": "Security Misconfiguration",
                    "name": "HTTP Redirects to HTTPS",
                    "severity": "Low",
                    "confidence": "High",
                    "description": (
                        "The HTTP endpoint redirects clients "
                        "to an HTTPS endpoint."
                    ),
                    "recommendation": (
                        "Prefer HTTPS URLs and consider enforcing "
                        "HTTPS across the application."
                    ),
                    "detection": "HTTP to HTTPS redirect",
                    "evidence": (
                        f"HTTP {response.status_code} response "
                        f"redirects to: {location}"
                    ),
                    "url": url,
                })

            else:

                findings.append({
                    "type": "Transport Security",
                    "category": "Security Misconfiguration",
                    "name": "Unencrypted HTTP",
                    "severity": "Medium",
                    "confidence": "High",
                    "description": (
                        "The target is accessible over plain HTTP "
                        "without an immediate HTTPS redirect."
                    ),
                    "recommendation": (
                        "Serve the application exclusively over HTTPS "
                        "and redirect HTTP traffic to HTTPS."
                    ),
                    "detection": "HTTP transport analysis",
                    "evidence": (
                        f"The target responded over HTTP with "
                        f"status {response.status_code} and did "
                        "not return an HTTPS redirect."
                    ),
                    "url": url,
                })

        except requests.RequestException:
            pass

        return findings

    # ========================================================
    # HTTPS
    # ========================================================

    if parsed.scheme.lower() != "https":
        return findings

    port = parsed.port or 443

    context = ssl.create_default_context()

    try:

        with socket.create_connection(
            (hostname, port),
            timeout=5,
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname,
            ) as tls_socket:

                certificate = (
                    tls_socket.getpeercert()
                )

                tls_version = (
                    tls_socket.version()
                )

                cipher = (
                    tls_socket.cipher()
                )

                # ------------------------------------------------
                # Certificate validity
                # ------------------------------------------------

                if not certificate:

                    findings.append({
                        "type": "TLS Security",
                        "category": "Security Misconfiguration",
                        "name": "Invalid TLS Certificate",
                        "severity": "High",
                        "confidence": "High",
                        "description": (
                            "The HTTPS endpoint did not provide a "
                            "certificate that could be validated."
                        ),
                        "recommendation": (
                            "Install a valid certificate issued for "
                            "the application's hostname."
                        ),
                        "detection": "TLS certificate validation",
                        "evidence": (
                            "TLS connection completed without a "
                            "valid peer certificate."
                        ),
                        "url": url,
                    })

                # ------------------------------------------------
                # Weak TLS protocol
                # ------------------------------------------------

                if tls_version in (
                    "TLSv1",
                    "TLSv1.1",
                ):

                    findings.append({
                        "type": "TLS Security",
                        "category": "Security Misconfiguration",
                        "name": "Deprecated TLS Version",
                        "severity": "High",
                        "confidence": "High",
                        "description": (
                            f"The server negotiated deprecated "
                            f"{tls_version}."
                        ),
                        "recommendation": (
                            "Disable TLS 1.0 and TLS 1.1 and use "
                            "modern TLS versions such as TLS 1.2 "
                            "or TLS 1.3."
                        ),
                        "detection": "TLS protocol analysis",
                        "evidence": (
                            f"Negotiated TLS version: {tls_version}"
                        ),
                        "url": url,
                    })

                # ------------------------------------------------
                # Record negotiated TLS information
                # ------------------------------------------------

                if tls_version:

                    findings.append({
                        "type": "TLS Information",
                        "category": "Informational",
                        "name": "TLS Configuration Observed",
                        "severity": "Low",
                        "confidence": "High",
                        "description": (
                            "The HTTPS endpoint successfully "
                            "negotiated a TLS connection."
                        ),
                        "recommendation": (
                            "Continue using current supported TLS "
                            "versions and periodically review TLS "
                            "configuration."
                        ),
                        "detection": "TLS handshake analysis",
                        "evidence": (
                            f"TLS version: {tls_version}; "
                            f"cipher: "
                            f"{cipher[0] if cipher else 'Unknown'}"
                        ),
                        "url": url,
                    })

    except ssl.SSLCertVerificationError as error:

        findings.append({
            "type": "TLS Security",
            "category": "Vulnerability",
            "name": "TLS Certificate Verification Failed",
            "severity": "High",
            "confidence": "High",
            "description": (
                "The HTTPS certificate could not be validated "
                "by the scanner."
            ),
            "recommendation": (
                "Install a valid certificate whose hostname and "
                "trust chain match the deployed application."
            ),
            "detection": "TLS certificate validation",
            "evidence": str(error),
            "url": url,
        })

    except (
        ssl.SSLError,
        socket.timeout,
        ConnectionError,
        OSError,
    ) as error:

        findings.append({
            "type": "TLS Security",
            "category": "Security Misconfiguration",
            "name": "TLS Connection Problem",
            "severity": "Medium",
            "confidence": "Medium",
            "description": (
                "The scanner could not establish a normal "
                "validated TLS connection."
            ),
            "recommendation": (
                "Review the server's TLS configuration and "
                "certificate deployment."
            ),
            "detection": "TLS connection analysis",
            "evidence": str(error),
            "url": url,
        })

    return findings