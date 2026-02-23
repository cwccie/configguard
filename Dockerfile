FROM python:3.14-slim

LABEL maintainer="Corey A. Wade <corey@coreywade.com>"
LABEL description="ConfigGuard — AI-driven network configuration compliance"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python package
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
COPY rules/ rules/
COPY sample_configs/ sample_configs/

RUN pip install --no-cache-dir .

# Expose ports for API and dashboard
EXPOSE 8080 5000

# Default: run the API
ENV CONFIGGUARD_HOST=0.0.0.0
ENV CONFIGGUARD_PORT=8080

CMD ["python", "-m", "flask", "--app", "configguard.api.app:create_app()", "run", "--host", "0.0.0.0", "--port", "8080"]
