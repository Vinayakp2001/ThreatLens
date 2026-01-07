# ThreatLens Backend Docker Image
# Updated for backend v2.0.0 structure

# Use Python 3.11 slim image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create storage directory with proper permissions
RUN mkdir -p /app/storage/repos \
    /app/storage/docs \
    /app/storage/embeddings \
    /app/storage/cache \
    /app/storage/backups \
    /app/storage/temp \
    /app/storage/logs \
    && chmod -R 755 /app/storage

# Set environment variables for new backend
ENV PYTHONPATH=/app
ENV STORAGE_BASE_PATH=/app/storage
ENV DATABASE_PATH=/app/storage/threat_modeling.db
ENV API_HOST=0.0.0.0
ENV API_PORT=8000

# Expose port
EXPOSE 8000

# Health check updated for new backend API
HEALTHCHECK --interval=30s --timeout=30s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the new backend application
CMD ["uvicorn", "backend.api.main:app", "--host", "0.0.0.0", "--port", "8000"]