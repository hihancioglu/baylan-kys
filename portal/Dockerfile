FROM python:3.12-slim
ENV PIP_NO_CACHE_DIR=1
WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends tesseract-ocr poppler-utils && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
RUN pip install libsass rcssmin jsmin
RUN python static/build.py
CMD ["python", "app.py"]
