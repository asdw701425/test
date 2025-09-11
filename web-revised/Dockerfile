FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 프런트 앱 + 템플릿/정적 리소스 포함
COPY app.py ./app.py
COPY templates/ ./templates/
COPY static/ ./static/

ENV PORT=8080
EXPOSE 8080
CMD ["python", "app.py"]
