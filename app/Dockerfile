FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY drift_detector.py .
COPY keys/ /app/keys/

RUN chmod 600 /app/keys/private_key.pem && chmod 644 /app/keys/public_key.pem

EXPOSE 5000
CMD ["gunicorn", "-b", "0.0.0.0:5000", "main:app"]