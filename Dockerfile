FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml ./
COPY src/ src/

RUN pip install --no-cache-dir ".[browser]" \
    && playwright install --with-deps chromium

EXPOSE 8080

CMD ["uvicorn", "stacklens.presentation.web.app:webapp", "--host", "0.0.0.0", "--port", "8080"]
