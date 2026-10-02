FROM python:3.11-slim

WORKDIR /app

# Install system dependencies needed by psycopg2 and some ML packages
# Retry apt-get to handle transient Docker DNS issues
RUN for i in 1 2 3; do \
      apt-get update && \
      apt-get install -y --no-install-recommends --fix-missing gcc libpq-dev && \
      break || { echo "apt attempt $i failed, retrying..."; sleep 5; }; \
    done && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir --no-deps fastapi==0.111.0

# Copy source (overridden by volume mount in docker-compose for live reload)
COPY . .

# Default command — overridden per-service in docker-compose.yml
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
