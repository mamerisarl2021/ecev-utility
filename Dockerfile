# ============================
# Stage 1 — Dependencies build
# ============================
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_HOME=/app \
    DEBIAN_FRONTEND=noninteractive

WORKDIR $APP_HOME

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    libdmtx0b \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --prefix=/usr/local --no-cache-dir -r requirements.txt


# ============================
# Stage 2 — Runtime
# ============================
FROM python:3.11-slim AS runtime

ENV APP_HOME=/app \
    DEBIAN_FRONTEND=noninteractive \
    PATH="/usr/local/bin:$PATH"

WORKDIR $APP_HOME

# Install minimal runtime deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    libpq-dev \
    libdmtx0b \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Copy python deps from builder
COPY --from=builder /usr/local /usr/local

# Copy code
COPY . $APP_HOME/

# Collect static files
RUN python manage.py collectstatic --noinput

# Copy nginx configuration
COPY nginx.conf /etc/nginx/sites-available/default
RUN ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/

# Entrypoint
RUN chmod +x entrypoint.sh

EXPOSE 8000

CMD ["sh", "-c", "gunicorn app.wsgi:application --bind 0.0.0.0:8000 --workers 3 & nginx -g 'daemon off;'"]
