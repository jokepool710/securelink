import pytest
from fastapi import HTTPException
from starlette.datastructures import UploadFile
from app.main import analyze_qr

@pytest.mark.asyncio
async def test_qr_rejects_non_image_before_decoding():
    upload = UploadFile(filename="payload.svg", file=__import__("io").BytesIO(b"<svg/>"), headers={"content-type":"image/svg+xml"})
    with pytest.raises(HTTPException) as exc:
        await analyze_qr(None, upload)
    assert exc.value.status_code == 415
