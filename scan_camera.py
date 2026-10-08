from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import secrets
import socket
import ssl
import struct
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any
from xml.etree import ElementTree
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlsplit, urlunsplit
from urllib.request import HTTPBasicAuthHandler, HTTPDigestAuthHandler, HTTPPasswordMgrWithDefaultRealm, HTTPRedirectHandler, HTTPSHandler, Request, build_opener

import cv2
import numpy as np
from flask import Flask, jsonify, render_template_string, request

cv2.utils.logging.setLogLevel(cv2.utils.logging.LOG_LEVEL_SILENT)
app = Flask(__name__)

HOST = os.environ.get("SCAN_CAMERA_HOST", "0.0.0.0")
PORT = 8092
PORT_SCAN_TIMEOUT = 0.18
PROBE_TIMEOUT = 0.35
MAX_WORKERS = 256
CHUNK_SIZE = 2048
MAX_JOBS = 4
MEDIA_TIMEOUT_MS = 2500
MEDIA_CANDIDATE_LIMIT = 100

jobs: dict[str, dict[str, Any]] = {}
jobs_lock = threading.Lock()

RTSPS_PORTS = {322, 8555}
HTTPS_PORTS = {443, 444, 8443, 9443}
KNOWN_PORTS = {
    21: "FTP probable",
    22: "SSH probable",
    23: "Telnet probable",
    53: "DNS probable",
    80: "HTTP probable",
    322: "RTSPS probable",
    81: "HTTP probable",
    88: "HTTP probable / service caméra",
    443: "HTTPS probable",
    554: "RTSP probable",
    8000: "HTTP probable / service caméra",
    8001: "Service caméra probable",
    8080: "HTTP probable",
    8081: "HTTP probable",
    8443: "HTTPS probable",
    8554: "RTSP probable",
    8555: "RTSPS probable",
    8899: "ONVIF probable",
    37777: "Service caméra/Dahua probable",
    9000: "Service caméra probable",
    34567: "Service caméra/XM probable",
}


def validate_target(value: str) -> str:
    """Accept a single private/local IPv4 or IPv6 address, never a subnet/hostname."""
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValueError("Saisissez une adresse IP valide (pas un nom d’hôte).") from exc
    if not (address.is_private or address.is_loopback or address.is_link_local):
        raise ValueError("Par sécurité, le scanner est limité aux adresses IP privées ou locales.")
    return str(address)


def _http_probe_evidence(response: bytes) -> str:
    lines = response.decode("iso-8859-1", errors="replace").splitlines()
    useful = [line.strip() for line in lines[:20] if line.lower().startswith(("http/", "server:", "www-authenticate:"))]
    return " · ".join(useful)[:240] or "Réponse HTTP reçue"


def probe_protocol(ip: str, port: int) -> dict[str, str]:
    """Fingerprint common services; keep port-based names explicitly probabilistic."""
    guess = KNOWN_PORTS.get(port)
    try:
        with socket.create_connection((ip, port), timeout=PROBE_TIMEOUT) as conn:
            conn.settimeout(PROBE_TIMEOUT)
            conn.sendall(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
            response = conn.recv(512)
            if b"RTSP/" in response:
                evidence = response.splitlines()[0].decode("ascii", errors="replace")[:120]
                return {"protocol": "RTSP", "confidence": "confirmé", "evidence": evidence}
    except (OSError, TimeoutError):
        pass

    try:
        with socket.create_connection((ip, port), timeout=PROBE_TIMEOUT) as conn:
            conn.settimeout(PROBE_TIMEOUT)
            conn.sendall(b"HEAD / HTTP/1.0\r\nHost: camera\r\nConnection: close\r\n\r\n")
            response = conn.recv(512)
            if response.startswith(b"HTTP/"):
                return {"protocol": "HTTP", "confidence": "confirmé", "evidence": _http_probe_evidence(response)}
    except (OSError, TimeoutError):
        pass

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=PROBE_TIMEOUT) as raw:
            raw.settimeout(PROBE_TIMEOUT)
            with context.wrap_socket(raw, server_hostname=ip) as secure:
                secure.settimeout(PROBE_TIMEOUT)
                tls_version = secure.version() or "TLS"
                try:
                    secure.sendall(b"HEAD / HTTP/1.0\r\nHost: camera\r\nConnection: close\r\n\r\n")
                    response = secure.recv(512)
                except (OSError, ssl.SSLError, TimeoutError):
                    response = b""
                if response.startswith(b"HTTP/"):
                    evidence = f"{tls_version} · {_http_probe_evidence(response)}"
                    return {"protocol": "HTTPS", "confidence": "confirmé", "evidence": evidence}
                try:
                    secure.sendall(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
                    response = secure.recv(512)
                except (OSError, ssl.SSLError, TimeoutError):
                    response = b""
                if b"RTSP/" in response:
                    evidence = response.splitlines()[0].decode("ascii", errors="replace")[:120]
                    return {"protocol": "RTSPS", "confidence": "confirmé", "evidence": f"{tls_version} · {evidence}"}
                return {"protocol": "TLS (service à identifier)", "confidence": "confirmé", "evidence": f"Handshake {tls_version} réussi; protocole applicatif inconnu"}
    except (OSError, ssl.SSLError, TimeoutError):
        pass

    return {
        "protocol": guess or "TCP ouvert · protocole non identifié",
        "confidence": "probable" if guess else "non identifié",
        "evidence": "Aucune signature de protocole reconnue; le port TCP est ouvert",
    }


def is_tcp_port_open(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=PORT_SCAN_TIMEOUT):
            return True
    except (OSError, TimeoutError):
        return False


def run_scan(job_id: str, ip: str) -> None:
    with jobs_lock:
        jobs[job_id]["status"] = "running"

    open_ports: list[int] = []
    for first in range(1, 65536, CHUNK_SIZE):
        chunk = range(first, min(first + CHUNK_SIZE, 65536))
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = {pool.submit(is_tcp_port_open, ip, port): port for port in chunk}
            for future in as_completed(futures):
                port = futures[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception:
                    pass
        completed = min(first + CHUNK_SIZE - 1, 65535)
        with jobs_lock:
            jobs[job_id].update({"completed": completed, "open_ports": sorted(open_ports)})

    results = [
        {"port": port, **probe_protocol(ip, port), "service": KNOWN_PORTS.get(port, "")}
        for port in sorted(open_ports)
    ]
    with jobs_lock:
        jobs[job_id].update({"status": "done", "completed": 65535, "open_ports": sorted(open_ports), "results": results})


def _fourcc_name(capture: cv2.VideoCapture) -> str | None:
    value = int(capture.get(cv2.CAP_PROP_FOURCC))
    if not value:
        return None
    name = "".join(chr((value >> (8 * index)) & 0xFF) for index in range(4)).strip("\x00 ")
    return name or None


def _probe_rtsp_media(url: str) -> dict[str, Any]:
    capture = None
    try:
        params = [
            cv2.CAP_PROP_OPEN_TIMEOUT_MSEC, MEDIA_TIMEOUT_MS,
            cv2.CAP_PROP_READ_TIMEOUT_MSEC, MEDIA_TIMEOUT_MS,
        ]
        capture = cv2.VideoCapture(url, cv2.CAP_FFMPEG, params)
        if not capture.isOpened():
            return {"ok": False, "format": "—", "codec": None, "width": None, "height": None}
        ok, frame = capture.read()
        if not ok or frame is None:
            return {"ok": False, "format": "—", "codec": None, "width": None, "height": None}
        height, width = frame.shape[:2]
        codec = _fourcc_name(capture)
        return {
            "ok": True,
            "format": "Flux RTSP",
            "codec": codec,
            "width": int(width),
            "height": int(height),
        }
    except Exception:
        return {"ok": False, "format": "—", "codec": None, "width": None, "height": None}
    finally:
        if capture is not None:
            capture.release()


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _http_url_without_userinfo(parsed) -> str:
    host = parsed.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    netloc = f"{host}:{parsed.port}" if parsed.port else host
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, ""))


def _onvif_operation(
    endpoint: str,
    namespace: str,
    operation: str,
    username: str,
    password: str,
    parameters: dict[str, str] | None = None,
):
    soap_ns = "http://www.w3.org/2003/05/soap-envelope"
    wsse_ns = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
    wsu_ns = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
    envelope = ElementTree.Element(f"{{{soap_ns}}}Envelope")
    if username or password:
        header = ElementTree.SubElement(envelope, f"{{{soap_ns}}}Header")
        security = ElementTree.SubElement(header, f"{{{wsse_ns}}}Security", {f"{{{soap_ns}}}mustUnderstand": "true"})
        token = ElementTree.SubElement(security, f"{{{wsse_ns}}}UsernameToken")
        ElementTree.SubElement(token, f"{{{wsse_ns}}}Username").text = username
        nonce = secrets.token_bytes(20)
        created = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        digest = hashlib.sha1(nonce + created.encode("utf-8") + password.encode("utf-8")).digest()
        ElementTree.SubElement(token, f"{{{wsse_ns}}}Password", {
            "Type": f"{wsse_ns}#PasswordDigest",
        }).text = base64.b64encode(digest).decode("ascii")
        ElementTree.SubElement(token, f"{{{wsse_ns}}}Nonce", {
            "EncodingType": f"{wsse_ns}#Base64Binary",
        }).text = base64.b64encode(nonce).decode("ascii")
        ElementTree.SubElement(token, f"{{{wsu_ns}}}Created").text = created

    body = ElementTree.SubElement(envelope, f"{{{soap_ns}}}Body")
    operation_element = ElementTree.SubElement(body, f"{{{namespace}}}{operation}")
    for name, value in (parameters or {}).items():
        ElementTree.SubElement(operation_element, f"{{{namespace}}}{name}").text = value
    action = f"{namespace}/{operation}"
    request_obj = Request(endpoint, data=ElementTree.tostring(envelope, encoding="utf-8", xml_declaration=True), headers={
        "Content-Type": f'application/soap+xml; charset=utf-8; action="{action}"',
        "SOAPAction": f'"{action}"',
        "User-Agent": "CameraFormatScanner/1.0",
    }, method="POST")
    password_manager = HTTPPasswordMgrWithDefaultRealm()
    if username or password:
        password_manager.add_password(None, endpoint, username, password)
    opener = build_opener(
        _NoRedirect(),
        HTTPBasicAuthHandler(password_manager),
        HTTPDigestAuthHandler(password_manager),
        HTTPSHandler(context=ssl._create_unverified_context()),
    )
    try:
        with opener.open(request_obj, timeout=MEDIA_TIMEOUT_MS / 1000) as response:
            response_body = response.read(2 * 1024 * 1024)
    except HTTPError as exc:
        try:
            response_body = exc.read(2 * 1024 * 1024)
        finally:
            exc.close()
    except (URLError, OSError, TimeoutError):
        return None
    try:
        return ElementTree.fromstring(response_body)
    except ElementTree.ParseError:
        return None


def _onvif_service_url(raw_url: str, camera_ip: str) -> str | None:
    try:
        parsed = urlsplit(raw_url)
        if parsed.scheme.lower() not in {"http", "https"}:
            return None
        if ipaddress.ip_address(parsed.hostname or "") != ipaddress.ip_address(camera_ip):
            return None
    except ValueError:
        return None
    return _http_url_without_userinfo(parsed)


def _probe_onvif_service(url: str) -> dict[str, Any]:
    """Verify ONVIF and detect advertised/configured PTZ without moving the camera."""
    parsed = urlsplit(url)
    endpoint = _http_url_without_userinfo(parsed)
    camera_ip = parsed.hostname or ""
    username = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    empty = {"ok": False, "format": "—", "codec": None, "width": None, "height": None}
    device_ns = "http://www.onvif.org/ver10/device/wsdl"
    media_ns = "http://www.onvif.org/ver10/media/wsdl"
    ptz_ns = "http://www.onvif.org/ver20/ptz/wsdl"

    response_root = _onvif_operation(endpoint, device_ns, "GetDeviceInformation", username, password)
    if response_root is None:
        return empty
    local_names = {
        element.tag.rsplit("}", 1)[-1]
        for element in response_root.iter()
        if isinstance(element.tag, str)
    }
    response_text = " ".join(element.text or "" for element in response_root.iter()).lower()
    if "GetDeviceInformationResponse" not in local_names:
        if "Fault" in local_names and any(
            marker in response_text for marker in ("notauthorized", "failedauthentication", "unauthorized")
        ):
            return {**empty, "state": "auth_required", "format": "ONVIF détecté · authentification requise"}
        return empty

    result: dict[str, Any] = {
        "ok": True,
        "state": "verified",
        "format": "Service ONVIF vérifié",
        "codec": None,
        "width": None,
        "height": None,
        "ptz_tested": False,
    }
    capabilities_root = _onvif_operation(endpoint, device_ns, "GetCapabilities", username, password, {"Category": "All"})
    if capabilities_root is None:
        return result
    capabilities = next((element for element in capabilities_root.iter() if element.tag.rsplit("}", 1)[-1] == "Capabilities"), None)
    if capabilities is None:
        return result
    ptz_element = next((element for element in capabilities if element.tag.rsplit("}", 1)[-1] == "PTZ"), None)
    result["ptz_tested"] = True
    result["ptz_supported"] = ptz_element is not None
    if ptz_element is None:
        return result

    ptz_xaddr = next(((element.text or "").strip() for element in ptz_element.iter() if element.tag.rsplit("}", 1)[-1] == "XAddr"), "")
    ptz_endpoint = _onvif_service_url(ptz_xaddr, camera_ip)
    if not ptz_endpoint:
        return result
    ptz_parsed = urlsplit(ptz_endpoint)
    result["ptz_supported"] = True
    result["ptz_port"] = ptz_parsed.port or (443 if ptz_parsed.scheme == "https" else 80)

    media_element = next((element for element in capabilities if element.tag.rsplit("}", 1)[-1] == "Media"), None)
    media_xaddr = next(((element.text or "").strip() for element in media_element.iter() if element.tag.rsplit("}", 1)[-1] == "XAddr"), "") if media_element is not None else ""
    media_endpoint = _onvif_service_url(media_xaddr, camera_ip)
    if media_endpoint:
        profiles_root = _onvif_operation(media_endpoint, media_ns, "GetProfiles", username, password)
        if profiles_root is not None:
            result["ptz_profiles"] = sum(
                1 for element in profiles_root.iter()
                if element.tag.rsplit("}", 1)[-1] == "PTZConfiguration"
            )

    nodes_root = _onvif_operation(ptz_endpoint, ptz_ns, "GetNodes", username, password)
    result["ptz_service_responded"] = nodes_root is not None and any(
        element.tag.rsplit("}", 1)[-1] == "PTZNode" for element in nodes_root.iter()
    )
    if result.get("ptz_profiles") and result["ptz_service_responded"]:
        result["format"] = "Service ONVIF vérifié · PTZ confirmé"
    return result


def _probe_dvrip_service(url: str) -> dict[str, Any]:
    """Test one explicit XM/DVRIP login attempt; never guess credentials."""
    parsed = urlsplit(url)
    username = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    empty = {"ok": False, "format": "—", "codec": None, "width": None, "height": None}
    if not username and not password:
        return {**empty, "state": "credentials_required", "format": "DVRIP/XM probable · identifiants requis"}

    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    password_digest = hashlib.md5(password.encode("utf-8")).digest()
    xm_password = "".join(alphabet[(password_digest[i] + password_digest[i + 1]) % len(alphabet)] for i in range(0, 16, 2))
    payload = json.dumps({
        "UserName": username,
        "PassWord": xm_password,
        "EncryptType": "MD5",
        "LoginType": "DVRIP-Web",
    }, separators=(",", ":")).encode("ascii")
    header_struct = struct.Struct("<BBxxIIBBHI")

    def read_exact(conn: socket.socket, length: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < length:
            chunk = conn.recv(length - len(chunks))
            if not chunk:
                raise OSError("Connexion fermée avant la réponse DVRIP complète")
            chunks.extend(chunk)
        return bytes(chunks)

    try:
        with socket.create_connection((parsed.hostname, parsed.port or 34567), timeout=MEDIA_TIMEOUT_MS / 1000) as conn:
            conn.settimeout(MEDIA_TIMEOUT_MS / 1000)
            conn.sendall(header_struct.pack(0xFF, 1, 0, 2, 0, 0, 1000, len(payload)) + payload)
            header = read_exact(conn, header_struct.size)
            magic, version, session_id, _number, _fragments, _fragment, message_type, length = header_struct.unpack(header)
            if magic != 0xFF or version != 1 or message_type != 1001 or length > 32768:
                return empty
            response = json.loads(read_exact(conn, length).decode("utf-8"))
            status = int(response.get("Ret", -1))
            if status == 100:
                session = response.get("SessionID")
                try:
                    numeric_session = int(str(session), 16)
                    logout = json.dumps({"Name": "", "SessionID": f"0x{numeric_session:08X}"}, separators=(",", ":")).encode("ascii")
                    conn.sendall(header_struct.pack(0xFF, 1, numeric_session, 4, 0, 0, 1002, len(logout)) + logout)
                except (TypeError, ValueError, OSError):
                    pass
                return {"ok": True, "state": "verified", "format": "Service DVRIP/XM authentifié", "codec": None, "width": None, "height": None}
            if status in {106, 203, 204}:
                return {**empty, "state": "auth_failed", "format": "Service DVRIP/XM confirmé · identifiants refusés"}
            if status in {205, 206}:
                return {**empty, "state": "auth_blocked", "format": "Service DVRIP/XM confirmé · compte verrouillé/bloqué"}
            return {**empty, "state": "service_detected", "format": f"Service DVRIP/XM confirmé · réponse {status}"}
    except (OSError, TimeoutError, ValueError, json.JSONDecodeError, struct.error):
        return empty


def _probe_http_media(url: str) -> dict[str, Any]:
    parsed = urlsplit(url)
    headers = {"Range": "bytes=0-2097151", "User-Agent": "CameraFormatScanner/1.0"}
    if parsed.username is not None:
        credentials = f"{unquote(parsed.username)}:{unquote(parsed.password or '')}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(credentials).decode("ascii")
    request_obj = Request(_http_url_without_userinfo(parsed), headers=headers)
    tls_context = ssl._create_unverified_context()
    password_manager = HTTPPasswordMgrWithDefaultRealm()
    if parsed.username is not None:
        password_manager.add_password(None, _http_url_without_userinfo(parsed), unquote(parsed.username), unquote(parsed.password or ""))
    opener = build_opener(
        _NoRedirect(),
        HTTPBasicAuthHandler(password_manager),
        HTTPDigestAuthHandler(password_manager),
        HTTPSHandler(context=tls_context),
    )
    try:
        with opener.open(request_obj, timeout=MEDIA_TIMEOUT_MS / 1000) as response:
            content_type = response.headers.get_content_type().lower()
            data = response.read(2 * 1024 * 1024)
    except (HTTPError, URLError, OSError, TimeoutError):
        return {"ok": False, "format": "—", "codec": None, "width": None, "height": None}

    empty_result = {"ok": False, "format": "—", "codec": None, "width": None, "height": None}
    ext_by_type = {
        "image/jpeg": ".jpg", "image/jpg": ".jpg", "image/png": ".png", "image/gif": ".gif",
        "image/webp": ".webp", "image/bmp": ".bmp", "video/mp4": ".mp4",
        "video/mpeg": ".mpeg", "video/webm": ".webm", "video/x-matroska": ".mkv",
        "video/x-msvideo": ".avi", "video/quicktime": ".mov", "video/x-flv": ".flv",
    }
    ext_by_path = {".jpeg": ".jpg", ".jpg": ".jpg", ".png": ".png", ".gif": ".gif", ".webp": ".webp", ".bmp": ".bmp", ".mp4": ".mp4", ".mkv": ".mkv", ".avi": ".avi", ".mov": ".mov", ".mjpeg": ".mjpeg"}
    filename = parsed.path.lower().rsplit("/", 1)[-1]
    path_ext = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""
    media_format = ext_by_type.get(content_type)
    if not media_format and content_type == "application/octet-stream":
        media_format = ext_by_path.get(path_ext)
    if not media_format and data.startswith(bytes((0xFF, 0xD8, 0xFF))):
        media_format = ".jpg"
        content_type = "image/jpeg"
    elif not media_format and data.startswith(bytes((0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A))):
        media_format = ".png"
        content_type = "image/png"
    elif not media_format and b"ftyp" in data[:64]:
        media_format = ".mp4"
        content_type = "video/mp4"
    if not media_format or not data or data.lstrip().lower().startswith((b"<!doctype html", b"<html")):
        return empty_result

    if content_type.startswith("image/") or media_format in {".jpg", ".png", ".gif", ".webp", ".bmp"}:
        frame = cv2.imdecode(np.frombuffer(data, dtype=np.uint8), cv2.IMREAD_UNCHANGED)
        if frame is None:
            return empty_result
        height, width = frame.shape[:2]
        return {"ok": True, "format": media_format, "codec": None, "width": int(width), "height": int(height)}

    if not content_type.startswith("video/") and content_type != "application/octet-stream":
        return empty_result
    if content_type == "application/octet-stream":
        video_signature_ok = (
            (media_format in {".mp4", ".mov"} and b"ftyp" in data[:64])
            or (media_format in {".mkv", ".webm"} and data.startswith(bytes((0x1A, 0x45, 0xDF, 0xA3))))
            or (media_format == ".avi" and data.startswith(b"RIFF") and data[8:12] == b"AVI ")
            or (media_format == ".mpeg" and data.startswith(bytes((0x00, 0x00, 0x01))))
        )
        if not video_signature_ok:
            return empty_result
    video_result = _probe_rtsp_media(url)
    return {
        "ok": True,
        "format": media_format,
        "codec": video_result["codec"] if video_result["ok"] else None,
        "width": video_result["width"] if video_result["ok"] else None,
        "height": video_result["height"] if video_result["ok"] else None,
    }


def _probe_media_candidate(candidate: dict[str, str]) -> dict[str, Any]:
    url = candidate["url"]
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() in {"rtsp", "rtsps"}:
            result = _probe_rtsp_media(url)
        elif parsed.scheme.lower() == "dvrip":
            result = _probe_dvrip_service(url)
        elif parsed.path.rstrip("/") == "/onvif/device_service":
            result = _probe_onvif_service(url)
        else:
            result = _probe_http_media(url)
    except Exception:
        result = {"ok": False, "format": "—", "codec": None, "width": None, "height": None}
    if result.get("ok"):
        result.setdefault("state", "verified")
    return {"candidate_id": candidate["candidate_id"], "label": candidate["label"], **result}


def run_media_probe(job_id: str, candidates: list[dict[str, str]]) -> None:
    with jobs_lock:
        jobs[job_id]["status"] = "running"
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(_probe_media_candidate, candidate): candidate for candidate in candidates}
        for index, future in enumerate(as_completed(futures), start=1):
            try:
                results.append(future.result())
            except Exception:
                candidate = futures[future]
                results.append({"ok": False, "candidate_id": candidate["candidate_id"], "label": candidate["label"], "format": "—", "codec": None, "width": None, "height": None})
            with jobs_lock:
                jobs[job_id].update({"completed": index, "results": list(results)})
    with jobs_lock:
        jobs[job_id].update({"status": "done", "results": results})


PAGE = r'''<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scanner de caméra IP</title>
<style>
:root{color-scheme:dark;--bg:#0b1118;--panel:#111b25;--line:#263746;--text:#eef5fa;--muted:#9badbb;--blue:#68b6ff;--green:#55dda2;--red:#ff8989}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 72% -16%,#18314a,transparent 55%),var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}main{max-width:1500px;margin:auto;padding:42px 22px 76px}.eyebrow{color:var(--blue);font-size:12px;font-weight:750;letter-spacing:.14em;text-transform:uppercase}h1{font-size:clamp(30px,5vw,48px);line-height:1.1;letter-spacing:-.04em;margin:10px 0}.intro{color:var(--muted);max-width:720px;margin:0 0 24px}.panel{background:linear-gradient(145deg,#131f2b,#101821);border:1px solid var(--line);border-radius:16px;padding:22px;box-shadow:0 20px 60px #0003}label{display:block;font-size:13px;font-weight:700;margin:14px 0 6px}.fields{display:grid;grid-template-columns:2fr 1fr 1fr;gap:12px}input{width:100%;background:#0a121a;border:1px solid #344658;border-radius:9px;padding:12px;color:var(--text);font:inherit}input:focus,button:focus-visible{outline:2px solid var(--blue);outline-offset:2px}button{border:0;border-radius:9px;padding:12px 16px;background:var(--blue);color:#07111b;font:700 14px system-ui;cursor:pointer;margin-top:16px}button:disabled{opacity:.6;cursor:wait}.hint,.status,.notice{color:var(--muted);font-size:12px}.status{min-height:22px;margin-top:12px}.progress{height:7px;background:#243442;border-radius:8px;overflow:hidden;margin-top:8px}.progress span{height:100%;display:block;width:0;background:var(--green);transition:width .2s}section.results{margin-top:25px}.section-head{display:flex;align-items:baseline;justify-content:space-between;gap:12px}h2{font-size:19px;margin:0 0 12px}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:12px}table{width:100%;border-collapse:collapse;min-width:520px}.media-table{min-width:1100px}.media-table td:nth-child(2){min-width:260px;max-width:560px;overflow-wrap:anywhere;font:12px ui-monospace,monospace}.media-table th:last-child,.media-table td:last-child{position:sticky;right:0;z-index:1;min-width:88px;background:#111b25}.media-table th:last-child{background:#14202b}th,td{text-align:left;padding:11px 13px;border-bottom:1px solid #22313e;font-size:13px}th{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);background:#14202b}tr:last-child td{border:0}.open{color:var(--green);font-weight:750}.empty{color:var(--muted);padding:18px}.urls{display:grid;gap:8px}.urlrow{display:flex;align-items:center;gap:10px;border:1px solid var(--line);background:#101922;border-radius:9px;padding:10px 12px}.url{flex:1;min-width:0;overflow-wrap:anywhere;font:12px/1.5 ui-monospace,monospace;color:#cedce7}.urlrow button{margin:0;background:#233849;color:#e0f0fc;padding:7px 10px;font-size:12px}.tag{font-size:11px;color:var(--blue);white-space:nowrap}.warning{border-left:3px solid #e7b85a;padding:8px 12px;background:#e7b85a10;color:#dfc68f;font-size:12px;margin-top:13px}@media(max-width:680px){main{padding:30px 15px 55px}.fields{grid-template-columns:1fr}.panel{padding:17px}.urlrow{align-items:flex-start;flex-wrap:wrap}.url{flex-basis:100%}}
</style>
</head><body><main>
<div class="eyebrow">Diagnostic local · réseau de confiance</div><h1>Scanner de caméra IP</h1>
<p class="intro">Saisissez l’IP et, si besoin, les identifiants. Le scan inventorie les ports TCP ouverts, sépare les protocoles confirmés des hypothèses, puis teste HTTP(S), ONVIF, RTSP et XM/DVRIP.</p>
<div class="panel"><form id="scan-form"><div class="fields">
<div><label for="ip">Adresse IP</label><input id="ip" name="ip" required autocomplete="off" placeholder="192.168.1.50"></div>
<div><label for="username">Utilisateur</label><input id="username" name="username" autocomplete="username" placeholder="admin"></div>
<div><label for="password">Mot de passe</label><input id="password" name="password" type="password" autocomplete="current-password"></div>
</div><button id="submit">Scanner tous les ports <span aria-hidden="true">→</span></button></form>
<div class="hint">Le scan de ports n’envoie que l’IP. Les tests transmettent temporairement les identifiants au serveur en HTTP non chiffré : utilisez uniquement un réseau de confiance. XM/DVRIP effectue au plus une tentative de connexion avec les identifiants saisis; aucune combinaison n’est devinée. Les identifiants ne sont pas enregistrés.</div>
<div class="status" id="status" role="status" aria-live="polite"></div><div class="progress" aria-hidden="true"><span id="bar"></span></div>
<div class="warning">N’utilisez cet outil que sur une caméra que vous possédez ou êtes autorisé à administrer. Le scan porte sur une seule adresse IP privée ou locale.</div></div>
<section class="results" id="ports-section" hidden><div class="section-head"><h2>Ports ouverts et protocoles</h2><span class="hint" id="port-count"></span></div><div class="table-wrap"><table><thead><tr><th>Port TCP</th><th>Protocole observé / hypothèse</th><th>Certitude</th><th>Preuve</th><th>Service suggéré par le numéro de port</th></tr></thead><tbody id="port-rows"></tbody></table></div></section>
<section class="results" id="urls-section" hidden><h2>Vérification des services et sources média</h2><p class="notice">Les chemins possibles restent cachés. Le test ONVIF vérifie aussi la présence du PTZ, ses profils et son port, en lecture seule (aucun mouvement n’est commandé).</p><p class="notice">Clique pour tester les flux vidéo, HTTP(S), ONVIF et le service propriétaire XM/DVRIP lorsqu’il est présent.</p><button id="probe-media" type="button">Tester les flux et services caméra</button><div class="status" id="url-status" role="status" aria-live="polite"></div></section>
<section class="results" id="media-section" hidden><div class="section-head"><h2>Résultats des tests média et services caméra</h2><span class="hint" id="media-count"></span></div><div class="table-wrap"><table class="media-table"><thead><tr><th>Source</th><th>URL complète</th><th>Format</th><th>Codec</th><th>Résolution</th><th>PTZ / port</th><th>État</th><th></th></tr></thead><tbody id="media-rows"></tbody></table></div><div class="status" id="media-status" role="status" aria-live="polite"></div></section>
</main><script>
const form=document.querySelector('#scan-form'),submit=document.querySelector('#submit'),statusEl=document.querySelector('#status'),bar=document.querySelector('#bar');
form.addEventListener('submit',async event=>{event.preventDefault();const ip=document.querySelector('#ip').value.trim(),username=document.querySelector('#username').value,password=document.querySelector('#password').value;submit.disabled=true;statusEl.textContent='Démarrage du scan…';bar.style.width='0%';document.querySelector('#ports-section').hidden=true;document.querySelector('#urls-section').hidden=true;document.querySelector('#media-section').hidden=true;
 try{const response=await fetch('/api/scans',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})});const data=await response.json();if(!response.ok)throw new Error(data.error||'Impossible de démarrer le scan.');window.scanId=data.id;await poll(data.id,ip,username,password)}catch(error){statusEl.textContent=error.message;submit.disabled=false}
});
async function poll(id,ip,username,password){const response=await fetch('/api/scans/'+id),job=await response.json();if(!response.ok)throw new Error(job.error||'Erreur de scan.');const percent=Math.round(job.completed/job.total*100);bar.style.width=percent+'%';statusEl.textContent=job.status==='done'?'Scan terminé.':`Scan TCP en cours… ${job.completed.toLocaleString('fr-FR')} / ${job.total.toLocaleString('fr-FR')} ports`;renderPorts(job.results||[],job.status==='done');if(job.status==='done'){renderUrls(ip,username,password,job.results||[]);submit.disabled=false;return}setTimeout(()=>poll(id,ip,username,password).catch(error=>{statusEl.textContent=error.message;submit.disabled=false}),500)}
function renderPorts(results,done){const section=document.querySelector('#ports-section'),body=document.querySelector('#port-rows');section.hidden=false;body.replaceChildren(...results.map(item=>{const row=document.createElement('tr');row.innerHTML=`<td class="open">${item.port}/tcp</td><td></td><td></td><td></td><td></td>`;row.children[1].textContent=item.protocol;row.children[2].textContent=item.confidence||'—';row.children[3].textContent=item.evidence||'—';row.children[4].textContent=item.service||'—';return row}));document.querySelector('#port-count').textContent=done?`${results.length} port(s) ouvert(s)`:`${results.length} port(s) ouvert(s) repéré(s)`;if(done&&!results.length){const row=document.createElement('tr');row.innerHTML='<td class="empty" colspan="5">Aucun port TCP ouvert détecté.</td>';body.append(row)}}
function encodeAuth(username,password){return username||password?`${encodeURIComponent(username)}:${encodeURIComponent(password)}@`:''}
function encodePathValue(value){return encodeURIComponent(value).replace(/_/g,'%5F')}
function renderUrls(ip,username,password,results){const section=document.querySelector('#urls-section'),candidates=[],auth=encodeAuth(username,password),host=ip.includes(':')?`[${ip}]`:ip;const add=(label,url)=>candidates.push({label,url});
 for(const item of results){const p=item.port,proto=item.protocol;if(proto==='RTSP'||proto==='RTSPS'||[322,554,8554,8555,10554,1554].includes(p)){const scheme=proto==='RTSPS'||[322,8555].includes(p)?'rtsps':'rtsp',base=`${scheme}://${auth}${host}:${p}`;add(`${p}/tcp · RTSP`,base+'/');add('Chemin caméra · flux principal',`${base}/user=${encodePathValue(username)}_password=${encodePathValue(password)}_channel=1_stream=0.sdp`);add('Chemin caméra · flux secondaire',`${base}/user=${encodePathValue(username)}_password=${encodePathValue(password)}_channel=1_stream=1.sdp`);for(const [label,path] of [['Dahua · principal','/cam/realmonitor?channel=1&subtype=0'],['Dahua · secondaire','/cam/realmonitor?channel=1&subtype=1'],['Hikvision · principal','/Streaming/Channels/101'],['Hikvision · secondaire','/Streaming/Channels/102'],['XM / générique · principal','/live/ch00_0'],['XM / générique · secondaire','/live/ch00_1'],['Générique · stream1','/stream1'],['Générique · stream2','/stream2'],['Générique · ch1 main','/ch1/main/av_stream'],['Générique · ch1 sub','/ch1/sub/av_stream']])add(label,base+path)}
 if(p===34567)add('XM/DVRIP · vérification du service',`dvrip://${auth}${host}:34567/`);
 if(['HTTP','HTTPS','TLS (service à identifier)'].includes(proto)||[80,81,88,443,444,8000,8080,8081,8443,8888,8899,9443].includes(p)){const scheme=['HTTPS','TLS (service à identifier)'].includes(proto)||[443,444,8443,9443].includes(p)?'https':'http',base=`${scheme}://${auth}${host}:${p}`;add(`${p}/tcp · ${scheme.toUpperCase()} interface`,base+'/');add('ONVIF · GetDeviceInformation',base+'/onvif/device_service');add('Image · snapshot.jpg',base+'/snapshot.jpg');add('Image · cgi-bin/snapshot.cgi',base+'/cgi-bin/snapshot.cgi');add('Image · ISAPI/Hikvision',base+'/ISAPI/Streaming/channels/101/picture');add('Image · webcapture caméra',base+'/webcapture.jpg?command=snap&channel=1');add('Image · jpg/image.jpg',base+'/jpg/image.jpg');add('Image · Dahua snapshot channel 1',base+'/cgi-bin/snapshot.cgi?channel=1');add('Image · CamHi snapshot',`${base}/snapshot.cgi?user=${encodeURIComponent(username)}&pwd=${encodeURIComponent(password)}`);add('Image · XM/Xiongmai snapshot',`${base}/tmpfs/auto.jpg?usr=${encodeURIComponent(username)}&pwd=${encodeURIComponent(password)}`);add('Image · XM/Xiongmai CGI',`${base}/cgi-bin/snapshot.cgi?chn=0&u=${encodeURIComponent(username)}&p=${encodeURIComponent(password)}`);add('Vidéo · video.mp4',base+'/video.mp4');add('Vidéo · live.mp4',base+'/live.mp4');add('Générique · API caméra',base+'/cgi-bin/')}
 }
 const unique=[...new Map(candidates.map(item=>[item.url,item])).values()];window.urlCandidates=unique;document.querySelector('#probe-media').disabled=unique.length===0;document.querySelector('#url-status').textContent=unique.length?`${unique.length} chemins à vérifier. Aucun ne sera présenté comme valide avant un test réussi.`:'Aucun service caméra reconnu à tester sur les ports ouverts.';section.hidden=false}
document.querySelector('#probe-media').addEventListener('click',async()=>{const candidates=window.urlCandidates||[];if(!candidates.length)return;const button=document.querySelector('#probe-media'),section=document.querySelector('#media-section');button.disabled=true;section.hidden=false;document.querySelector('#media-status').textContent='Démarrage des tests…';document.querySelector('#media-rows').replaceChildren();try{const response=await fetch('/api/media-probes',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scan_id:window.scanId,candidates:candidates.map(({label,url})=>({label,url}))})});const data=await response.json();if(!response.ok)throw new Error(data.error||'Impossible de tester les flux.');await pollMedia(data.id)}catch(error){document.querySelector('#media-status').textContent=error.message;button.disabled=false}});
async function pollMedia(id){const response=await fetch('/api/scans/'+id),job=await response.json();if(!response.ok)throw new Error(job.error||'Erreur de test média.');renderMedia(job.results||[],job.completed,job.total,job.status==='done');document.querySelector('#media-status').textContent=job.status==='done'?'Analyse terminée.':`Analyse des sources… ${job.completed} / ${job.total}`;if(job.status==='done'){document.querySelector('#probe-media').disabled=false;document.querySelector('#password').value='';return}setTimeout(()=>pollMedia(id).catch(error=>{document.querySelector('#media-status').textContent=error.message;document.querySelector('#probe-media').disabled=false}),500)}
function renderMedia(results,completed,total,done){const body=document.querySelector('#media-rows'),visible=results.filter(item=>item.ok||['auth_required','auth_failed','auth_blocked','credentials_required','service_detected'].includes(item.state)),verified=visible.filter(item=>item.ok),stateLabels={auth_required:'Service détecté · authentification requise',auth_failed:'Service confirmé · identifiants refusés',auth_blocked:'Service confirmé · compte bloqué',credentials_required:'XM/DVRIP probable · identifiants requis',service_detected:'Service détecté · accès refusé'};document.querySelector('#media-count').textContent=done?`${verified.length} vérifiée(s) · ${visible.length-verified.length} détectée(s) sans accès · ${total} test(s)`:`${verified.length} vérifiée(s) · ${completed}/${total} testées`;body.replaceChildren(...visible.map(item=>{const row=document.createElement('tr'),url=window.urlCandidates?.[Number(item.candidate_id)]?.url||'',state=stateLabels[item.state]||'Vérifiée',ptz=item.ptz_tested?(item.ptz_supported?`${item.ptz_service_responded&&item.ptz_profiles?'Confirmé':'Annoncé'} · ${item.ptz_port?`${item.ptz_port}/tcp`:'port à confirmer'}${item.ptz_profiles?` · ${item.ptz_profiles} profil(s)`:''}`:'Non annoncé par ONVIF'):(item.format?.includes('ONVIF')||item.label.toLowerCase().includes('onvif')?'Non vérifiable':'—');for(const value of [item.label,url,item.format,item.codec||'—',item.width&&item.height?`${item.width} × ${item.height}`:'—',ptz,state]){const cell=document.createElement('td');cell.textContent=value;row.append(cell)}const action=document.createElement('td');if(item.ok){const copy=document.createElement('button');copy.textContent='Copier';copy.addEventListener('click',async()=>{await navigator.clipboard.writeText(url);copy.textContent='Copié';setTimeout(()=>copy.textContent='Copier',1100)});action.append(copy)}else action.textContent='—';row.append(action);return row}));if(done&&!visible.length){const row=document.createElement('tr'),cell=document.createElement('td');cell.colSpan=8;cell.className='empty';cell.textContent='Aucun flux média ou service additionnel confirmé parmi les chemins testés.';row.append(cell);body.append(row)}}
</script></body></html>'''


@app.get("/")
def index():
    return render_template_string(PAGE)


@app.post("/api/scans")
def start_scan():
    payload = request.get_json(silent=True) or {}
    raw_ip = payload.get("ip", "")
    if not isinstance(raw_ip, str) or not raw_ip.strip():
        return jsonify(error="Saisissez l’adresse IP de la caméra."), 400
    try:
        ip = validate_target(raw_ip)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    with jobs_lock:
        for key in list(jobs):
            if jobs[key]["status"] == "done" and time.time() - jobs[key]["created"] > 1800:
                del jobs[key]
        if sum(job["status"] != "done" for job in jobs.values()) >= MAX_JOBS:
            return jsonify(error="Trop de scans actifs. Réessayez plus tard."), 429
        job_id = uuid.uuid4().hex
        jobs[job_id] = {"status": "queued", "created": time.time(), "ip": ip, "completed": 0, "total": 65535, "open_ports": [], "results": []}
    threading.Thread(target=run_scan, args=(job_id, ip), daemon=True).start()
    return jsonify(id=job_id), 202


@app.post("/api/media-probes")
def start_media_probe():
    payload = request.get_json(silent=True) or {}
    scan_id = payload.get("scan_id")
    candidates = payload.get("candidates")
    if not isinstance(scan_id, str) or not isinstance(candidates, list) or not candidates:
        return jsonify(error="Résultats de scan ou URLs candidates manquants."), 400
    if len(candidates) > MEDIA_CANDIDATE_LIMIT:
        return jsonify(error="Trop d’URLs à tester en une fois."), 400

    with jobs_lock:
        scan = jobs.get(scan_id)
        if scan is None or scan.get("status") != "done":
            return jsonify(error="Le scan des ports doit être terminé avant le test média."), 400
        ip = scan["ip"]
        open_ports = {item["port"] for item in scan["results"]}

    validated: list[dict[str, str]] = []
    for candidate_id, item in enumerate(candidates):
        if not isinstance(item, dict) or not isinstance(item.get("url"), str):
            return jsonify(error="URL candidate invalide."), 400
        raw_url = item["url"]
        if len(raw_url) > 4096:
            return jsonify(error="URL candidate trop longue."), 400
        try:
            parsed = urlsplit(raw_url)
            candidate_ip = ipaddress.ip_address(parsed.hostname or "")
            default_port = 554 if parsed.scheme.lower() == "rtsp" else 322 if parsed.scheme.lower() == "rtsps" else 34567 if parsed.scheme.lower() == "dvrip" else 443 if parsed.scheme.lower() == "https" else 80
            port = parsed.port if parsed.port is not None else default_port
        except ValueError:
            return jsonify(error="URL candidate invalide."), 400
        scheme = parsed.scheme.lower()
        if candidate_ip != ipaddress.ip_address(ip) or port not in open_ports:
            return jsonify(error="Les URLs doivent viser uniquement l’IP et les ports ouverts du scan."), 400
        if scheme not in {"rtsp", "rtsps", "http", "https", "dvrip"}:
            return jsonify(error="Protocole média non pris en charge."), 400
        label = item.get("label", "Source caméra")
        validated.append({"candidate_id": str(candidate_id), "label": str(label)[:100], "url": raw_url})

    with jobs_lock:
        if sum(job["status"] != "done" for job in jobs.values()) >= MAX_JOBS:
            return jsonify(error="Trop de tâches actives. Réessayez plus tard."), 429
        job_id = uuid.uuid4().hex
        jobs[job_id] = {"status": "queued", "created": time.time(), "completed": 0, "total": len(validated), "results": []}
    threading.Thread(target=run_media_probe, args=(job_id, validated), daemon=True).start()
    return jsonify(id=job_id), 202


@app.get("/api/scans/<job_id>")
def scan_status(job_id: str):
    with jobs_lock:
        job = jobs.get(job_id)
        if job is None:
            return jsonify(error="Scan introuvable ou expiré."), 404
        return jsonify({key: job[key] for key in ("status", "completed", "total", "results")})


if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
