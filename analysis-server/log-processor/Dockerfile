FROM python:3.11-slim

WORKDIR /app

# 시스템 의존성 설치 (psycopg2 등을 위해 필요)
RUN apt-get update && apt-get install -y libpq-dev gcc && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# 로그가 즉시 터미널에 보이도록 설정
ENV PYTHONUNBUFFERED=1

CMD ["python", "main.py"]