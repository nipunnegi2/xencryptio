from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import ssl, socket, requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
from urllib.parse import urlparse
from cryptography.hazmat.primitives import hashes
from cryptography.x509.ocsp import OCSPRequestBuilder
import datetime
import dns.resolver

app = FastAPI()

class URLRequest(BaseModel):
    urls: str  # comma-separated URLs



def get_certificate_chain(hostname: str, port: int = 443):
    """Get complete certificate chain"""
    try:
        cert_chain = ssl.get_server_certificate_chain((hostname, port))
        chain_info = []
        
        for i, cert_pem in enumerate(cert_chain):
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            chain_info.append({
                "position": i,
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "is_ca": cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca if cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS) else False,
                "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex()
            })
        
        return chain_info
    except Exception:
        return []

def check_security_headers(url: str):
    """Check HTTP security headers"""
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        headers = response.headers
        
        return {
            "hsts": "Strict-Transport-Security" in headers,
            "hsts_value": headers.get("Strict-Transport-Security", ""),
            "hpkp": "Public-Key-Pins" in headers,
            "csp": "Content-Security-Policy" in headers,
            "x_frame_options": "X-Frame-Options" in headers
        }
    except Exception:
        return {}

def check_dns_records(hostname: str):
    """Check DNS CAA and TLSA records"""
    dns_info = {}
    
    try:
        # CAA records
        caa_records = []
        try:
            answers = dns.resolver.resolve(hostname, 'CAA')
            caa_records = [str(rdata) for rdata in answers]
        except:
            pass
        dns_info["caa_records"] = caa_records
        
        # TLSA records
        tlsa_records = []
        try:
            answers = dns.resolver.resolve(f"_443._tcp.{hostname}", 'TLSA')
            tlsa_records = [str(rdata) for rdata in answers]
        except:
            pass
        dns_info["tlsa_records"] = tlsa_records
        
    except Exception:
        pass
    
    return dns_info

def get_protocol_cipher_info(tls_version: str, cipher_name: str):
    """Extract protocol and cipher information"""
    cipher_components = []
    component_types = ["RC4", "DES", "3DES", "AES", "ChaCha20", "MD5", "SHA", "SHA256", "SHA384", "NULL", "ECDHE", "DHE", "RSA"]
    for component in component_types:
        if component in cipher_name:
            cipher_components.append(component)
    
    forward_secrecy = ("ECDHE" in cipher_name or "DHE" in cipher_name)
    
    return {
        "protocol_version": tls_version,
        "cipher_components": cipher_components,
        "ephemeral_key_exchange": forward_secrecy
    }

def get_elliptic_curve_info(cert):
    """Extract elliptic curve information"""
    try:
        pubkey = cert.public_key()
        if hasattr(pubkey, 'curve'):
            return {
                "curve_name": pubkey.curve.name,
                "key_size": pubkey.curve.key_size
            }
    except:
        pass
    return {}

def check_certificate_transparency(cert):
    """Check for Certificate Transparency extensions"""
    try:
        # SCT (Signed Certificate Timestamps) extension
        sct_ext = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2"))
        return {"ct_present": True, "sct_count": len(sct_ext.value)}
    except:
        return {"ct_present": False}

def fetch_crypto_details(hostname: str, port: int = 443):
    try:
        # SSL context
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:

                # TLS info
                tls_version = ssock.version()
                cipher_suite = {
                    "name": ssock.cipher()[0],
                    "protocol": ssock.cipher()[1],
                    "strength_bits": ssock.cipher()[2]
                }

                # Certificate
                cert_bin = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_bin, default_backend())

                pubkey = cert.public_key()
                pubkey_algo = pubkey.__class__.__name__
                pubkey_bits = pubkey.key_size

                # Fingerprints - multiple hash algorithms
                fingerprints = {
                    "md5": cert.fingerprint(hashes.MD5()).hex(),
                    "sha1": cert.fingerprint(hashes.SHA1()).hex(),
                    "sha256": cert.fingerprint(hashes.SHA256()).hex(),
                    "sha384": cert.fingerprint(hashes.SHA384()).hex(),
                    "sha512": cert.fingerprint(hashes.SHA512()).hex()
                }

                # Extensions
                try:
                    san = cert.extensions.get_extension_for_oid(
                        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                    ).value.get_values_for_type(x509.DNSName)
                except Exception:
                    san = []

                try:
                    key_usage = cert.extensions.get_extension_for_oid(
                        ExtensionOID.KEY_USAGE
                    ).value.__dict__
                except Exception:
                    key_usage = {}

                try:
                    ext_key_usage = [
                        str(eku) for eku in cert.extensions.get_extension_for_oid(
                            ExtensionOID.EXTENDED_KEY_USAGE
                        ).value
                    ]
                except Exception:
                    ext_key_usage = []

                try:
                    basic_constraints = cert.extensions.get_extension_for_oid(
                        ExtensionOID.BASIC_CONSTRAINTS
                    ).value.__dict__
                except Exception:
                    basic_constraints = {}

                try:
                    crl_dist_points = [
                        dp.full_name[0].value
                        for dp in cert.extensions.get_extension_for_oid(
                            ExtensionOID.CRL_DISTRIBUTION_POINTS
                        ).value
                    ]
                except Exception:
                    crl_dist_points = []

                try:
                    aia = cert.extensions.get_extension_for_oid(
                        ExtensionOID.AUTHORITY_INFORMATION_ACCESS
                    ).value
                    ocsp_urls = [d.access_location.value for d in aia
                                 if d.access_method == AuthorityInformationAccessOID.OCSP]
                    ca_issuers = [d.access_location.value for d in aia
                                  if d.access_method == AuthorityInformationAccessOID.CA_ISSUERS]
                except Exception:
                    ocsp_urls, ca_issuers = [], []

                # Policy information
                try:
                    policies = cert.extensions.get_extension_for_oid(
                        ExtensionOID.CERTIFICATE_POLICIES
                    ).value
                    policy_oids = [str(policy.policy_identifier) for policy in policies]
                except Exception:
                    policy_oids = []

                # OCSP Must Staple
                try:
                    ocsp_must_staple = cert.extensions.get_extension_for_oid(
                        x509.ObjectIdentifier("1.3.6.1.5.5.7.1.24")
                    ) is not None
                except Exception:
                    ocsp_must_staple = False

                # Get additional crypto info
                cert_chain = get_certificate_chain(hostname, port)
                security_headers = check_security_headers(f"https://{hostname}")
                dns_info = check_dns_records(hostname)
                protocol_cipher_info = get_protocol_cipher_info(tls_version, cipher_suite["name"])
                ec_info = get_elliptic_curve_info(cert)
                ct_info = check_certificate_transparency(cert)

                # OCSP stapling check
                try:
                    ocsp_resp = ssock.ocsp_response
                    ocsp_stapling = ocsp_resp is not None
                except Exception:
                    ocsp_stapling = None

                return {
                    "tls": {
                        "version": tls_version,
                        "cipher_suite": cipher_suite
                    },
                    "certificate": {
                        "subject": cert.subject.rfc4514_string(),
                        "issuer": cert.issuer.rfc4514_string(),
                        "serial_number": str(cert.serial_number),
                        "version": cert.version.name,
                        "not_before": cert.not_valid_before.isoformat(),
                        "not_after": cert.not_valid_after.isoformat(),
                        "signature_algorithm": cert.signature_hash_algorithm.name,
                        "fingerprints": fingerprints,
                        "public_key": {
                            "algorithm": pubkey_algo,
                            "size_bits": pubkey_bits,
                            "elliptic_curve": ec_info
                        },
                        "extensions": {
                            "subject_alternative_names": san,
                            "key_usage": key_usage,
                            "extended_key_usage": ext_key_usage,
                            "basic_constraints": basic_constraints,
                            "crl_distribution_points": crl_dist_points,
                            "ocsp_urls": ocsp_urls,
                            "ca_issuers": ca_issuers,
                            "certificate_policies": policy_oids,
                            "ocsp_must_staple": ocsp_must_staple
                        },
                        "certificate_transparency": ct_info
                    },
                    "certificate_chain": cert_chain,
                    "crypto_analysis": {
                        "cipher_components": protocol_cipher_info["cipher_components"],
                        "ephemeral_key_exchange": protocol_cipher_info["ephemeral_key_exchange"],
                        "cipher_suite_breakdown": {
                            "key_exchange": "ECDHE" if "ECDHE" in cipher_suite["name"] else "DHE" if "DHE" in cipher_suite["name"] else "RSA" if "RSA" in cipher_suite["name"] else "Unknown",
                            "authentication": "ECDSA" if pubkey_algo == "ECPublicKey" else "RSA" if pubkey_algo == "RSAPublicKey" else pubkey_algo,
                            "encryption": "AES" if "AES" in cipher_suite["name"] else "ChaCha20" if "ChaCha20" in cipher_suite["name"] else "Unknown",
                            "hash": "SHA384" if "SHA384" in cipher_suite["name"] else "SHA256" if "SHA256" in cipher_suite["name"] else "Unknown"
                        },
                        "ocsp_stapling_active": ocsp_stapling,
                        "certificate_chain_validated": True  # If SSL connection succeeded
                    },
                    "security_headers": security_headers,
                    "dns_security": dns_info,
                    "active_configuration": {
                        "tls_version": tls_version,
                        "cipher_strength_bits": cipher_suite["strength_bits"],
                        "key_size_bits": pubkey_bits,
                        "signature_algorithm": cert.signature_hash_algorithm.name,
                        "encryption_standard": "AES" if "AES" in cipher_suite["name"] else "ChaCha20" if "ChaCha20" in cipher_suite["name"] else "Other"
                    }
                }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Crypto check failed: {e}")


@app.post("/crypto-audit")
async def crypto_audit(request: URLRequest):
    urls = [u.strip() for u in request.urls.split(",") if u.strip()]
    if not urls:
        raise HTTPException(status_code=400, detail="No valid URLs provided.")

    results = {}
    for url in urls:
        hostname = urlparse(url).hostname
        if not hostname:
            results[url] = {"error": "Invalid URL"}
            continue
        try:
            results[url] = fetch_crypto_details(hostname)
        except Exception as e:
            results[url] = {"error": str(e)}

    return results