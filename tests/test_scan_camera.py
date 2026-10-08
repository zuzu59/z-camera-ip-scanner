import io
import unittest
from email.message import Message
from urllib.error import HTTPError
from unittest.mock import patch

import cv2
import numpy as np
import scan_camera
from scan_camera import validate_target


class CameraTargetValidationTests(unittest.TestCase):
    def test_accepts_private_and_loopback_addresses(self):
        self.assertEqual(validate_target(" 192.168.1.50 "), "192.168.1.50")
        self.assertEqual(validate_target("127.0.0.1"), "127.0.0.1")
        self.assertEqual(validate_target("::1"), "::1")

    def test_rejects_public_ip_and_hostnames(self):
        with self.assertRaises(ValueError):
            validate_target("8.8.8.8")
        with self.assertRaises(ValueError):
            validate_target("camera.local")


class ProtocolFingerprintingTests(unittest.TestCase):
    def test_http_auth_challenge_is_confirmed_and_server_header_is_reported(self):
        class Connection:
            def __init__(self, response):
                self.response = response

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def settimeout(self, timeout):
                pass

            def sendall(self, data):
                pass

            def recv(self, limit):
                return self.response

        responses = [
            Connection(b""),
            Connection(b"HTTP/1.0 401 Unauthorized\r\nServer: Boa/0.94\r\nWWW-Authenticate: Digest\r\n\r\n"),
        ]
        with patch.object(scan_camera.socket, "create_connection", side_effect=responses):
            result = scan_camera.probe_protocol("192.168.1.50", 80)

        self.assertEqual(result["protocol"], "HTTP")
        self.assertEqual(result["confidence"], "confirmé")
        self.assertIn("401 Unauthorized", result["evidence"])
        self.assertIn("Server: Boa/0.94", result["evidence"])


class MediaFormatDetectionTests(unittest.TestCase):
    def test_jpeg_snapshot_reports_format_and_dimensions(self):
        encoded, buffer = cv2.imencode(".jpg", np.zeros((40, 80, 3), dtype=np.uint8))
        self.assertTrue(encoded)
        headers = Message()
        headers["Content-Type"] = "application/octet-stream"

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, limit):
                return buffer.tobytes()

        Response.headers = headers
        with patch.object(scan_camera, "build_opener") as build_opener:
            build_opener.return_value.open.return_value = Response()
            result = scan_camera._probe_http_media("http://192.168.1.50:80/cgi-bin/snapshot.cgi")
        self.assertTrue(result["ok"])
        self.assertEqual(result["format"], ".jpg")
        self.assertEqual((result["width"], result["height"]), (80, 40))

    def test_html_error_page_is_not_reported_as_a_verified_image(self):
        headers = Message()
        headers["Content-Type"] = "text/html"

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, limit):
                return b"<html>Not found</html>"

        Response.headers = headers
        with patch.object(scan_camera, "build_opener") as build_opener:
            build_opener.return_value.open.return_value = Response()
            result = scan_camera._probe_http_media("http://192.168.1.50:80/snapshot.jpg")
        self.assertFalse(result["ok"])

    def test_dvrip_probe_identifies_service_from_authentication_reply(self):
        reply_json = b'{"Ret":106,"SessionID":"0x00000000"}'
        packet = scan_camera.struct.pack("<BBxxIIBBHI", 0xFF, 1, 0, 2, 0, 0, 1001, len(reply_json)) + reply_json

        class Connection:
            def __init__(self):
                self.response = bytearray(packet)
                self.request = b""

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def settimeout(self, timeout):
                pass

            def sendall(self, data):
                self.request = data

            def recv(self, length):
                result = bytes(self.response[:length])
                del self.response[:length]
                return result

        connection = Connection()
        with patch.object(scan_camera.socket, "create_connection", return_value=connection):
            result = scan_camera._probe_dvrip_service(
                "dvrip://admin:temporary-secret@192.168.1.50:34567/"
            )

        self.assertEqual(result["state"], "auth_failed")
        self.assertFalse(result["ok"])
        self.assertIn("DVRIP/XM confirmé", result["format"])
        self.assertNotIn(b"temporary-secret", connection.request)
        self.assertEqual(scan_camera.struct.unpack("<BBxxIIBBHI", connection.request[:20])[1], 1)
        self.assertEqual(scan_camera.struct.unpack("<BBxxIIBBHI", connection.request[:20])[6], 1000)

    def test_dvrip_success_sends_logout_and_reports_authenticated_service(self):
        reply_json = b'{"Ret":100,"SessionID":"0x12345678"}'
        packet = scan_camera.struct.pack("<BBxxIIBBHI", 0xFF, 1, 0x12345678, 3, 0, 0, 1001, len(reply_json)) + reply_json

        class Connection:
            def __init__(self):
                self.response = bytearray(packet)
                self.requests = []

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def settimeout(self, timeout):
                pass

            def sendall(self, data):
                self.requests.append(data)

            def recv(self, length):
                result = bytes(self.response[:length])
                del self.response[:length]
                return result

        connection = Connection()
        with patch.object(scan_camera.socket, "create_connection", return_value=connection):
            result = scan_camera._probe_dvrip_service(
                "dvrip://admin:correct-secret@192.168.1.50:34567/"
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["state"], "verified")
        packet_header = scan_camera.struct.Struct("<BBxxIIBBHI")
        self.assertEqual([packet_header.unpack(request[:20])[6] for request in connection.requests], [1000, 1002])
        self.assertEqual(packet_header.unpack(connection.requests[1][:20])[2], 0x12345678)
        self.assertNotIn(b"correct-secret", b"".join(connection.requests))

    def test_dvrip_probe_does_not_attempt_login_without_credentials(self):
        with patch.object(scan_camera.socket, "create_connection") as create_connection:
            result = scan_camera._probe_dvrip_service("dvrip://192.168.1.50:34567/")
        self.assertEqual(result["state"], "credentials_required")
        create_connection.assert_not_called()

    def test_onvif_probe_sends_get_device_information_with_password_digest(self):
        response_body = (
            b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
            b'xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><s:Body>'
            b'<tds:GetDeviceInformationResponse><tds:Manufacturer>Camera</tds:Manufacturer>'
            b'</tds:GetDeviceInformationResponse></s:Body></s:Envelope>'
        )

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, limit):
                return response_body

        with patch.object(scan_camera, "build_opener") as build_opener:
            build_opener.return_value.open.return_value = Response()
            result = scan_camera._probe_onvif_service(
                "http://admin:temporary-secret@192.168.1.50:8899/onvif/device_service"
            )

        request_obj = build_opener.return_value.open.call_args_list[0].args[0]
        self.assertEqual(request_obj.get_method(), "POST")
        self.assertIn(b"GetDeviceInformation", request_obj.data)
        self.assertIn(b"PasswordDigest", request_obj.data)
        self.assertNotIn(b"temporary-secret", request_obj.data)
        self.assertTrue(result["ok"])
        self.assertEqual(result["format"], "Service ONVIF vérifié")

    def test_onvif_probe_detects_ptz_and_reports_its_port(self):
        responses = [
            b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><s:Body><tds:GetDeviceInformationResponse/></s:Body></s:Envelope>',
            b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema"><s:Body><tds:GetCapabilitiesResponse><tds:Capabilities><tt:Media><tt:XAddr>http://192.168.1.50:8899/onvif/media_service</tt:XAddr></tt:Media><tt:PTZ><tt:XAddr>http://192.168.1.50:8899/onvif/ptz_service</tt:XAddr></tt:PTZ></tds:Capabilities></tds:GetCapabilitiesResponse></s:Body></s:Envelope>',
            b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema"><s:Body><trt:GetProfilesResponse><trt:Profiles token="profile0"><tt:PTZConfiguration token="ptz0"/></trt:Profiles></trt:GetProfilesResponse></s:Body></s:Envelope>',
            b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl"><s:Body><tptz:GetNodesResponse><tptz:PTZNode token="node0"/></tptz:GetNodesResponse></s:Body></s:Envelope>',
        ]

        class Response:
            def __init__(self, body):
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, limit):
                return self.body

        with patch.object(scan_camera, "build_opener") as build_opener:
            build_opener.return_value.open.side_effect = [Response(body) for body in responses]
            result = scan_camera._probe_onvif_service(
                "http://admin:temporary-secret@192.168.1.50:8899/onvif/device_service"
            )

        self.assertTrue(result["ok"])
        self.assertTrue(result["ptz_tested"])
        self.assertTrue(result["ptz_supported"])
        self.assertTrue(result["ptz_service_responded"])
        self.assertEqual(result["ptz_profiles"], 1)
        self.assertEqual(result["ptz_port"], 8899)
        self.assertIn("PTZ confirmé", result["format"])
        for call in build_opener.return_value.open.call_args_list:
            self.assertNotIn(b"temporary-secret", call.args[0].data)

    def test_onvif_capabilities_without_ptz_report_not_announced(self):
        responses = [
            b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><s:Body><tds:GetDeviceInformationResponse/></s:Body></s:Envelope>',
            b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema"><s:Body><tds:GetCapabilitiesResponse><tds:Capabilities><tt:Media><tt:XAddr>http://192.168.1.50:8899/onvif/media_service</tt:XAddr></tt:Media></tds:Capabilities></tds:GetCapabilitiesResponse></s:Body></s:Envelope>',
        ]

        class Response:
            def __init__(self, body):
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, limit):
                return self.body

        with patch.object(scan_camera, "build_opener") as build_opener:
            build_opener.return_value.open.side_effect = [Response(body) for body in responses]
            result = scan_camera._probe_onvif_service("http://192.168.1.50:8899/onvif/device_service")

        self.assertTrue(result["ptz_tested"])
        self.assertFalse(result["ptz_supported"])
        self.assertNotIn("ptz_port", result)
        self.assertEqual(build_opener.return_value.open.call_count, 2)

    def test_onvif_authentication_fault_is_detected_but_not_verified(self):
        fault = (
            b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
            b'xmlns:ter="http://www.onvif.org/ver10/error"><s:Body><s:Fault>'
            b'<s:Code><s:Value>ter:NotAuthorized</s:Value></s:Code>'
            b'</s:Fault></s:Body></s:Envelope>'
        )
        http_error = HTTPError(
            "http://192.168.1.50:80/onvif/device_service", 500,
            "Server Error", {}, io.BytesIO(fault),
        )
        with patch.object(scan_camera, "build_opener") as build_opener:
            build_opener.return_value.open.side_effect = http_error
            result = scan_camera._probe_onvif_service(
                "http://192.168.1.50:80/onvif/device_service"
            )
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "auth_required")

    def test_rtsp_probe_reports_codec_and_resolution(self):
        class Capture:
            def isOpened(self):
                return True

            def read(self):
                return True, np.zeros((360, 640, 3), dtype=np.uint8)

            def get(self, prop):
                if prop == cv2.CAP_PROP_FOURCC:
                    return sum(ord(char) << (8 * index) for index, char in enumerate("H264"))
                return 0

            def release(self):
                pass

        with patch.object(scan_camera.cv2, "VideoCapture", return_value=Capture()):
            result = scan_camera._probe_rtsp_media("rtsp://192.168.1.50:554/live")
        self.assertTrue(result["ok"])
        self.assertEqual(result["format"], "Flux RTSP")
        self.assertEqual(result["codec"], "H264")
        self.assertEqual((result["width"], result["height"]), (640, 360))


class MediaProbeApiTests(unittest.TestCase):
    def setUp(self):
        self.client = scan_camera.app.test_client()
        with scan_camera.jobs_lock:
            scan_camera.jobs.clear()
            scan_camera.jobs["completed-scan"] = {
                "status": "done",
                "created": 0,
                "ip": "192.168.1.50",
                "results": [{"port": 554, "protocol": "RTSP"}, {"port": 34567, "protocol": "Service caméra/XM probable"}],
            }

    def test_media_probe_is_limited_to_scanned_ip_and_open_port(self):
        response = self.client.post(
            "/api/media-probes",
            json={
                "scan_id": "completed-scan",
                "candidates": [{"label": "bad", "url": "rtsp://192.168.1.51:554/"}],
            },
        )
        self.assertEqual(response.status_code, 400)

    def test_dvrip_candidate_is_scoped_to_the_scanned_open_port(self):
        with patch.object(scan_camera.threading, "Thread") as thread:
            response = self.client.post(
                "/api/media-probes",
                json={
                    "scan_id": "completed-scan",
                    "candidates": [{
                        "label": "XM/DVRIP",
                        "url": "dvrip://admin:temporary-secret@192.168.1.50:34567/",
                    }],
                },
            )

        self.assertEqual(response.status_code, 202)
        thread.assert_called_once()
        self.assertIn("temporary-secret", thread.call_args.kwargs["args"][1][0]["url"])
        job_id = response.get_json()["id"]
        self.assertNotIn("temporary-secret", str(scan_camera.jobs[job_id]))

    def test_credentials_in_candidate_urls_are_not_saved_or_returned(self):
        with patch.object(scan_camera.threading, "Thread") as thread:
            response = self.client.post(
                "/api/media-probes",
                json={
                    "scan_id": "completed-scan",
                    "candidates": [{
                        "label": "Flux principal",
                        "url": "rtsp://admin:temporary-secret@192.168.1.50:554/",
                    }],
                },
            )
        self.assertEqual(response.status_code, 202)
        job_id = response.get_json()["id"]
        self.assertNotIn("temporary-secret", response.get_data(as_text=True))
        self.assertNotIn("temporary-secret", repr(scan_camera.jobs[job_id]))
        thread.return_value.start.assert_called_once()


if __name__ == "__main__":
    unittest.main()
