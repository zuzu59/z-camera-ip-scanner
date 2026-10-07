import unittest
from email.message import Message
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
                "results": [{"port": 554, "protocol": "RTSP"}],
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
