# SecureQA Sentinel — backend (Flask) image
# Place this file at the project root: secureqa-sentinel/Dockerfile

FROM python:3.11-slim

WORKDIR /app

# gcc needed for building a couple of wheels (e.g. some SQLAlchemy/reportlab deps
# don't always ship prebuilt wheels for slim images)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copies everything in the build context except what .dockerignore excludes
# (frontend/, venv/, nginx/, scans.db, __pycache__, etc.)
COPY . .

EXPOSE 5000

ENV PYTHONUNBUFFERED=1

CMD ["python", "app.py"]