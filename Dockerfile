# Stage 1: Builder stage for Python dependencies
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_HOME=/app \
    DEBIAN_FRONTEND=noninteractive

WORKDIR $APP_HOME

# # Optimisation : Utiliser un miroir rapide + grouper apt-get en une seule commande
# RUN apt-get update \
#     && apt-get install -y --no-install-recommends \
#        build-essential \
#        libpq-dev \
#        ca-certificates \
#     && apt-get clean && rm -rf /var/lib/apt/lists/*

# Builder (pour installer les dépendances compilées)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential \
       libpq-dev \
       ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Runtime (seulement les bibliothèques nécessaires)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       nginx \
       ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*


# Installer les dépendances Python avec un cache
COPY requirements.txt .
RUN pip install --prefix=/usr/local --no-cache-dir -r requirements.txt

# Stage 2: Runtime stage
FROM python:3.11-slim AS runtime

ENV APP_HOME=/app \
    PATH="/usr/local/bin:$PATH" \
    DEBIAN_FRONTEND=noninteractive

WORKDIR $APP_HOME

# Optimisation : Grouper apt-get update et install en une seule commande
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       libpq-dev \
       nginx \
       ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copier uniquement les dépendances Python nécessaires
COPY --from=builder /usr/local /usr/local

# Copier le code de l'application
COPY . $APP_HOME/

# Collecter les fichiers statiques
RUN python manage.py collectstatic --noinput

# Configurer Nginx
COPY ./nginx.conf /etc/nginx/sites-available/default
RUN ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/

# Donner les permissions nécessaires
RUN chmod +x $APP_HOME/entrypoint.sh

EXPOSE 8000

CMD ["sh", "-c", "gunicorn config.wsgi:application --bind 0.0.0.0:8000 --workers 3 & nginx -g 'daemon off;'"]
