from fastapi.testclient import TestClient
import io
import cv2
from PIL import Image
from app.main import app

def test_qr_rejects_non_image_before_decoding():
    response = TestClient(app).post(
        "/api/analyze/qr",
        files={"file": ("payload.svg", b"<svg/>", "image/svg+xml")},
    )
    assert response.status_code == 415

def test_qr_decodes_wifi_payload_with_the_production_decoder():
    image = cv2.QRCodeEncoder_create().encode("WIFI:T:WPA;S:SecureLinkLab;P:test;;")
    image = cv2.resize(image, None, fx=10, fy=10, interpolation=cv2.INTER_NEAREST)
    ok, encoded = cv2.imencode(".png", image)
    assert ok
    response = TestClient(app).post(
        "/api/analyze/qr",
        files={"file": ("wifi.png", encoded.tobytes(), "image/png")},
    )
    assert response.status_code == 200
    assert response.json()["payload_type"] == "wifi"

def test_qr_url_uses_the_same_ssrf_protected_url_analyzer():
    image = cv2.QRCodeEncoder_create().encode("http://127.0.0.1/")
    image = cv2.resize(image, None, fx=10, fy=10, interpolation=cv2.INTER_NEAREST)
    ok, encoded = cv2.imencode(".png", image)
    assert ok
    response = TestClient(app).post(
        "/api/analyze/qr",
        files={"file": ("private-url.png", encoded.tobytes(), "image/png")},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["payload_type"] == "url"
    assert body["analysis"]["redirects"][-1]["blocked_reason"] == "Destination is a non-public address"

def test_qr_rejects_mime_spoofing_before_decoding():
    image = cv2.QRCodeEncoder_create().encode("not a URL")
    ok, encoded = cv2.imencode(".png", image)
    assert ok
    response = TestClient(app).post(
        "/api/analyze/qr",
        files={"file": ("suspicious.jpg", encoded.tobytes(), "image/jpeg")},
    )
    assert response.status_code == 415

def test_qr_rejects_corrupt_allowed_image_data():
    response = TestClient(app).post(
        "/api/analyze/qr",
        files={"file": ("corrupt.png", b"not a PNG", "image/png")},
    )
    assert response.status_code == 422

def test_qr_rejects_over_limit_dimensions_before_opencv_decode():
    image = Image.new("1", (5_000, 4_001))
    body = io.BytesIO()
    image.save(body, format="PNG")
    response = TestClient(app).post(
        "/api/analyze/qr",
        files={"file": ("large.png", body.getvalue(), "image/png")},
    )
    assert response.status_code == 413
