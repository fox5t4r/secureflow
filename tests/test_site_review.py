import io
import socket
import unittest
from unittest.mock import Mock, patch

from secureflow.site_review import review_site, site_endpoint


def dns_record(address):
    return (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 80))


class SiteReviewTests(unittest.TestCase):
    def test_public_request_uses_validated_ip_and_original_host(self):
        connection = Mock()
        connection.makefile.return_value = io.BytesIO(
            b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/\r\nContent-Length: 0\r\n\r\n"
        )
        with (
            patch(
                "secureflow.site_review.socket.getaddrinfo", return_value=[dns_record("8.8.8.8")]
            ) as dns,
            patch(
                "secureflow.site_review.socket.create_connection", return_value=connection
            ) as connect,
        ):
            result = review_site("http://example.com/docs/")
        dns.assert_called_once_with("example.com.", 80, type=socket.SOCK_STREAM)
        self.assertEqual(connect.call_count, 1)
        self.assertEqual(connect.call_args.args[0], ("8.8.8.8", 80))
        request = connection.sendall.call_args.args[0]
        self.assertIn(b"HEAD /docs/ HTTP/1.1\r\nHost: example.com\r\n", request)
        self.assertEqual(result["findings"][0]["state"], "inconclusive")

    def test_mixed_dns_result_is_rejected_before_connection(self):
        with (
            patch(
                "secureflow.site_review.socket.getaddrinfo",
                return_value=[dns_record("8.8.8.8"), dns_record("127.0.0.1")],
            ),
            patch("secureflow.site_review.socket.create_connection") as connect,
            self.assertRaisesRegex(ValueError, "공개 인터넷 주소"),
        ):
            review_site("http://example.com/")
        connect.assert_not_called()

    def test_public_registration_does_not_send_traffic(self):
        with patch("secureflow.site_review.socket.getaddrinfo") as dns:
            parsed, address, port = site_endpoint("https://example.com/docs/")
        dns.assert_not_called()
        self.assertEqual((parsed.path, address, port), ("/docs/", None, 443))
