import io
import cv2, numpy as np
from PIL import Image, UnidentifiedImageError
from fastapi import FastAPI, File, HTTPException, UploadFile, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from .config import settings
from .models import AnalyzeURLRequest, AnalysisResult, QRResult
from .service import analyze

limiter=Limiter(key_func=get_remote_address, default_limits=["30/minute"])
MAX_IMAGE_PIXELS = 20_000_000
IMAGE_MIME_BY_FORMAT = {"PNG": "image/png", "JPEG": "image/jpeg", "WEBP": "image/webp"}


def documentation_routes(environment: str) -> tuple[str | None, str | None, str | None]:
    """Keep the API schema and interactive documentation off public production instances."""
    if environment.strip().casefold() == "production":
        return None, None, None
    return "/docs", "/redoc", "/openapi.json"


docs_url, redoc_url, openapi_url = documentation_routes(settings.environment)
app=FastAPI(title="SecureLink API", version="0.1.0", docs_url=docs_url, redoc_url=redoc_url, openapi_url=openapi_url)
app.state.limiter=limiter; app.add_middleware(SlowAPIMiddleware)
app.add_middleware(CORSMiddleware,allow_origins=[x.strip() for x in settings.allowed_origins.split(",")],allow_methods=["POST","GET"],allow_headers=["Content-Type"],allow_credentials=False)
@app.exception_handler(RateLimitExceeded)
async def limited(request:Request, exc:RateLimitExceeded): return JSONResponse(status_code=429,content={"detail":"Too many requests"})
@app.get("/api/health")
@limiter.exempt
async def health(): return {"status":"ok"}
@app.post("/api/analyze/url",response_model=AnalysisResult)
@limiter.limit("10/minute")
async def analyze_url(request:Request,payload:AnalyzeURLRequest):
    try:return await analyze(payload.url,payload.external_intelligence)
    except ValueError as exc: raise HTTPException(422,str(exc))
@app.post("/api/analyze/qr",response_model=QRResult)
@limiter.limit("6/minute")
async def analyze_qr(request:Request,file:UploadFile=File(...)):
    allowed={"image/png","image/jpeg","image/webp"}
    if file.content_type not in allowed: raise HTTPException(415,"Only PNG, JPEG, and WebP images are accepted")
    body=await file.read(settings.max_upload_bytes+1)
    if len(body)>settings.max_upload_bytes: raise HTTPException(413,"Image exceeds 5 MB limit")
    try:
        with Image.open(io.BytesIO(body)) as probe:
            actual_mime = IMAGE_MIME_BY_FORMAT.get(probe.format or "")
            width, height = probe.size
    except (UnidentifiedImageError, OSError):
        raise HTTPException(422, "Invalid image data")
    if actual_mime is None or actual_mime != file.content_type:
        raise HTTPException(415, "Image content does not match its declared type")
    if width * height > MAX_IMAGE_PIXELS:
        raise HTTPException(413, "Image dimensions exceed the 20 megapixel limit")
    array=np.frombuffer(body,np.uint8); image=cv2.imdecode(array,cv2.IMREAD_COLOR)
    if image is None: raise HTTPException(422,"Invalid image data")
    decoded,_,_=cv2.QRCodeDetector().detectAndDecode(image)
    if not decoded: raise HTTPException(422,"No decodable QR code found")
    if decoded.lower().startswith(("http://","https://")): return QRResult(payload_type="url",extracted_content=decoded,analysis=await analyze(decoded))
    kind="wifi" if decoded.startswith("WIFI:") else "text"
    return QRResult(payload_type=kind,extracted_content=decoded,analysis=None)
