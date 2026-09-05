from fastapi.testclient import TestClient
import cv2
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
