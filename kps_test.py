#!/usr/bin/env python3
"""
KPS (Kimlik Paylaşım Sistemi) service tester.

Replicates the full WS-Trust / WS-Security flow used by KpsServiceImpl.java:
  1. Fetch a SAML token from the STS endpoint (username/password)
  2. Sign a KPS query with HMAC-SHA1 using the proof key
  3. Parse the result

Edit the CONFIG section or pass CLI arguments to change endpoints/credentials.

Usage:
    python kps_test.py --username USR --password PWD \
        --tc 12345678901 --name AD --surname SOYAD --birth 01-01-1990

    # Override endpoints (e.g. point at a test/mock service):
    python kps_test.py --sts-url https://... --kps-url https://... ...

    # Print raw SOAP envelopes and responses:
    python kps_test.py --verbose ...

Requirements:
    pip install requests lxml
"""

import argparse
import base64
import hashlib
import hmac as _hmac
import sys
import uuid
from datetime import datetime, timezone, timedelta
from io import BytesIO

import requests
from lxml import etree

# ── CONFIG (defaults; all overridable via CLI) ────────────────────────────────
STS_URL  = 'https://kimlikdogrulama.nvi.gov.tr/services/issuer.svc/IWSTrust13'
KPS_URL  = 'https://kpsv2.nvi.gov.tr/Services/RoutingService.svc'
USERNAME = ''
PASSWORD = ''

DEFAULT_TC      = ''
DEFAULT_NAME    = ''
DEFAULT_SURNAME = ''
DEFAULT_BIRTH   = ''   # DD-MM-YYYY
# ─────────────────────────────────────────────────────────────────────────────


# ── Crypto helpers ────────────────────────────────────────────────────────────

def _canonicalize(xml_str: str) -> bytes:
    """Exclusive XML C14N — matches Java's Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS."""
    root = etree.fromstring(xml_str.encode('utf-8'))
    buf = BytesIO()
    root.getroottree().write_c14n(buf, exclusive=True, with_comments=False)
    return buf.getvalue()


def _sha1(data: bytes) -> bytes:
    return hashlib.sha1(data).digest()


def _hmac_sha1(data: bytes, key: bytes) -> bytes:
    return _hmac.new(key, data, hashlib.sha1).digest()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


# ── Timestamp ────────────────────────────────────────────────────────────────

def _timestamp_element() -> str:
    now     = datetime.now(timezone.utc).replace(microsecond=0)
    expires = now + timedelta(minutes=5)
    fmt = '%Y-%m-%dT%H:%M:%SZ'
    return (
        '<wsu:Timestamp wsu:Id="_0" '
        'xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'
        f'<wsu:Created>{now.strftime(fmt)}</wsu:Created>'
        f'<wsu:Expires>{expires.strftime(fmt)}</wsu:Expires>'
        '</wsu:Timestamp>'
    )


# ── STS request ──────────────────────────────────────────────────────────────

def _build_sts_envelope(username: str, password: str) -> str:
    ts = _timestamp_element()
    token_id = str(uuid.uuid4())
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:wsa="http://www.w3.org/2005/08/addressing" '
        'xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" '
        'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" '
        'xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">'
        '<s:Header><wsse:Security>'
        f'{ts}'
        f'<wsse:UsernameToken wsu:Id="{token_id}">'
        f'<wsse:Username>{username}</wsse:Username>'
        f'<wsse:Password>{password}</wsse:Password>'
        '</wsse:UsernameToken></wsse:Security>'
        '<wsa:To>https://kimlikdogrulama.nvi.gov.tr/services/issuer.svc/IWSTrust13</wsa:To>'
        '<wsa:Action>http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue</wsa:Action>'
        '</s:Header>'
        '<s:Body>'
        '<wst:RequestSecurityToken xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">'
        '<wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>'
        '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">'
        '<wsa:EndpointReference>'
        '<wsa:Address>https://kpsv2.nvi.gov.tr/Services/RoutingService.svc</wsa:Address>'
        '</wsa:EndpointReference>'
        '</wsp:AppliesTo>'
        '</wst:RequestSecurityToken>'
        '</s:Body>'
        '</s:Envelope>'
    )


def _parse_sts_response(xml_str: str):
    """Returns (token_xml: str, proof_key: bytes, saml_assign_id: str)."""
    root = etree.fromstring(xml_str.encode('utf-8'))

    token_nodes = root.xpath("//*[local-name()='RequestedSecurityToken']/*[1]")
    if not token_nodes:
        raise ValueError('No RequestedSecurityToken in STS response')
    token_xml = etree.tostring(token_nodes[0], encoding='unicode')

    proof_nodes = root.xpath("//*[local-name()='BinarySecret']")
    if not proof_nodes:
        raise ValueError('No BinarySecret in STS response')
    proof_key = base64.b64decode(proof_nodes[0].text.strip())

    # Java: xpath.evaluate("//*[local-name()='KeyIdentifier']/text()", document)
    ki_nodes = root.xpath("//*[local-name()='KeyIdentifier']")
    saml_assign_id = ki_nodes[0].text.strip() if ki_nodes else ''

    return token_xml, proof_key, saml_assign_id


def fetch_sts_token(sts_url: str, username: str, password: str, verbose: bool = False):
    envelope = _build_sts_envelope(username, password)
    print(f'\n── STS REQUEST ──────────────────────────────────\n{envelope}\n')
    print(f'[STS] Requesting token from {sts_url} ...')
    resp = requests.post(
        sts_url,
        data=envelope.encode('utf-8'),
        headers={
            'Content-Type': 'application/soap+xml; charset=utf-8',
            'Connection': 'close',
        },
        timeout=10,
    )
    print(f'[STS] HTTP {resp.status_code}')
    print(f'\n── STS RESPONSE ─────────────────────────────────\n{resp.text}\n')

    if resp.status_code != 200:
        raise RuntimeError(f'STS request failed (HTTP {resp.status_code})')

    return _parse_sts_response(resp.text)


# ── KPS request ───────────────────────────────────────────────────────────────

def _build_signed_info(ts_xml: str) -> str:
    digest = _b64(_sha1(_canonicalize(ts_xml)))
    return (
        '<dsig:SignedInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">'
        '<dsig:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
        '<dsig:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1"/>'
        '<dsig:Reference URI="#_0">'
        '<dsig:Transforms>'
        '<dsig:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></dsig:Transform>'
        '</dsig:Transforms>'
        '<dsig:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>'
        f'<dsig:DigestValue>{digest}</dsig:DigestValue>'
        '</dsig:Reference>'
        '</dsig:SignedInfo>'
    )


def _build_signature(signed_info_xml: str, proof_key: bytes, saml_assign_id: str) -> str:
    sig_value = _b64(_hmac_sha1(_canonicalize(signed_info_xml), proof_key))
    return (
        f'<dsig:Signature>{signed_info_xml}'
        f'<dsig:SignatureValue>{sig_value}</dsig:SignatureValue>'
        '<dsig:KeyInfo>'
        '<wsse:SecurityTokenReference '
        'b:TokenType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1">'
        '<wsse:KeyIdentifier '
        'ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID">'
        f'{saml_assign_id}'
        '</wsse:KeyIdentifier>'
        '</wsse:SecurityTokenReference>'
        '</dsig:KeyInfo>'
        '</dsig:Signature>'
    )


def _build_kps_envelope(token_xml: str, proof_key: bytes, saml_assign_id: str,
                         tc: str, name: str, surname: str, birth: str) -> str:
    # birth: DD-MM-YYYY → parts[0]=day, parts[1]=month, parts[2]=year
    day, month, year = birth.split('-')

    body = (
        '<tns:Sorgula xmlns:tns="http://kps.nvi.gov.tr/2025/08/01">'
        '<tns:kriterListesi>'
        '<tns:TumKutukDogrulamaSorguKriteri>'
        f'<tns:Ad>{name}</tns:Ad>'
        f'<tns:DogumAy>{month}</tns:DogumAy>'
        f'<tns:DogumGun>{day}</tns:DogumGun>'
        f'<tns:DogumYil>{year}</tns:DogumYil>'
        f'<tns:KimlikNo>{tc}</tns:KimlikNo>'
        f'<tns:Soyad>{surname}</tns:Soyad>'
        '</tns:TumKutukDogrulamaSorguKriteri>'
        '</tns:kriterListesi>'
        '</tns:Sorgula>'
    )

    ts = _timestamp_element()
    signed_info = _build_signed_info(ts)
    signature   = _build_signature(signed_info, proof_key, saml_assign_id)

    header = (
        f'<wsse:Security>{ts}{token_xml}{signature}</wsse:Security>'
        '<wsa:To>https://kpsv2.nvi.gov.tr/Services/RoutingService.svc</wsa:To>'
        '<wsa:Action>http://kps.nvi.gov.tr/2025/08/01/TumKutukDogrulaServis/Sorgula</wsa:Action>'
    )

    return (
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:wsa="http://www.w3.org/2005/08/addressing" '
        'xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" '
        'xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" '
        'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" '
        'xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512" '
        'xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" '
        'xmlns:b="http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd">'
        f'<s:Header>{header}</s:Header>'
        f'<s:Body>{body}</s:Body>'
        '</s:Envelope>'
    )


def _parse_kps_response(xml_str: str, tc: str) -> bool:
    root = etree.fromstring(xml_str.encode('utf-8'))

    # Check top-level and child HataBilgisi (error) nodes
    for node in root.xpath("//*[local-name()='HataBilgisi']"):
        text = (node.text or '').strip()
        if text:
            print(f'[KPS] Error: {text}')
            return False

    is_foreign = tc.startswith('99') or tc.startswith('98')
    if is_foreign:
        foreign_nodes = root.xpath("//*[local-name()='YabanciKisiKutukleri']")
        if not foreign_nodes:
            print('[KPS] No citizen record found for foreign national')
            return False
        nat_nodes = root.xpath(
            "//*[local-name()='YabanciKisiKutukleri']"
            "//*[local-name()='TemelBilgisi']/*[local-name()='Uyruk']"
        )
        nationality = nat_nodes[0].text if nat_nodes else '(unknown)'
        print(f'[KPS] Foreign national record found. Nationality in KPS: {nationality}')

    return True


def verify_identity(kps_url: str, token_xml: str, proof_key: bytes, saml_assign_id: str,
                    tc: str, name: str, surname: str, birth: str, verbose: bool = False) -> bool:
    envelope = _build_kps_envelope(token_xml, proof_key, saml_assign_id, tc, name, surname, birth)
    if verbose:
        print(f'\n── KPS REQUEST ──────────────────────────────────\n{envelope}\n')

    print(f'\n── KPS REQUEST ──────────────────────────────────\n{envelope}\n')
    print(f'[KPS] Sending verification to {kps_url} ...')
    resp = requests.post(
        kps_url,
        data=envelope.encode('utf-8'),
        headers={
            'Content-Type': 'application/soap+xml; charset=utf-8',
            'Connection': 'close',
        },
        timeout=15,
    )
    print(f'[KPS] HTTP {resp.status_code}')
    print(f'\n── KPS RESPONSE ─────────────────────────────────\n{resp.text}\n')

    if resp.status_code != 200:
        return False

    return _parse_kps_response(resp.text, tc)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='KPS identity verification tester — mirrors KpsServiceImpl.java',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--sts-url',  default=STS_URL,  metavar='URL', help='STS token issuer URL')
    parser.add_argument('--kps-url',  default=KPS_URL,  metavar='URL', help='KPS routing service URL')
    parser.add_argument('--username', default=USERNAME,  help='STS username')
    parser.add_argument('--password', default=PASSWORD,  help='STS password')
    parser.add_argument('--tc',       default=DEFAULT_TC,      help='TC Kimlik No (11 digits)')
    parser.add_argument('--name',     default=DEFAULT_NAME,    help='First name (uppercase)')
    parser.add_argument('--surname',  default=DEFAULT_SURNAME, help='Last name (uppercase)')
    parser.add_argument('--birth',    default=DEFAULT_BIRTH,   metavar='DD-MM-YYYY', help='Birth date')
    parser.add_argument('--verbose',  action='store_true', help='Print raw SOAP envelopes')
    args = parser.parse_args()

    required = [('--username', args.username), ('--password', args.password),
                ('--tc', args.tc), ('--name', args.name),
                ('--surname', args.surname), ('--birth', args.birth)]
    missing = [flag for flag, val in required if not val]
    if missing:
        print(f'ERROR: missing: {", ".join(missing)}', file=sys.stderr)
        parser.print_help()
        sys.exit(1)

    print(f'\nVerifying: TC={args.tc}  Name={args.name} {args.surname}  Birth={args.birth}\n')

    try:
        token_xml, proof_key, saml_assign_id = fetch_sts_token(
            args.sts_url, args.username, args.password, verbose=args.verbose
        )
        print(f'[STS] Token acquired. SAML ID: {saml_assign_id[:50] if saml_assign_id else "(empty)"}')

        result = verify_identity(
            args.kps_url, token_xml, proof_key, saml_assign_id,
            args.tc, args.name, args.surname, args.birth,
            verbose=args.verbose,
        )

        print()
        if result:
            print('✓  VERIFIED — identity confirmed by KPS')
        else:
            print('✗  NOT VERIFIED — KPS rejected the identity')
        sys.exit(0 if result else 1)

    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        print(f'\nERROR: {e}', file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(2)


if __name__ == '__main__':
    main()
