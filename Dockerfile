FROM python:3.12-slim AS api
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend /app
RUN useradd --system --no-create-home securelink && chown -R securelink /app
USER securelink
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
