FROM python:3.12-slim
ENV PIP_NO_CACHE_DIR=1
WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends tesseract-ocr poppler-utils && \
    rm -rf /var/lib/apt/lists/*

# copy portal requirements first to leverage Docker layer cache
COPY portal/requirements.txt ./requirements.txt
RUN pip install -r requirements.txt

# copy application source into /app/portal to preserve package structure
COPY portal ./portal
COPY alembic.ini ./
COPY alembic ./alembic

RUN pip install libsass rcssmin jsmin
RUN python portal/static/build.py

# run database migrations before starting the app
CMD ["sh", "-c", "alembic upgrade head && python portal/app.py"]
