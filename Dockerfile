# Dockerfile for FlowVault Backend (FastAPI + Celery)

# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set work directory
WORKDIR /app

# Install system dependencies required for Playwright and potentially other libraries
# Note: Playwright browser binaries will be installed via playwright install command later
RUN apt-get update && apt-get install -y --no-install-recommends \
    # System deps for playwright, if any are missed by playwright install
    # For example, libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 libcairo2 libasound2
    # However, `playwright install --with-deps` should handle most of these.
    # Adding basic build tools just in case some Python packages need them
    build-essential \
    # For psycopg2 (PostgreSQL adapter) if not using psycopg2-binary or if it needs compilation
    libpq-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*


# Install pipenv (or just use requirements.txt directly if preferred)
# For simplicity with Render, using requirements.txt is often easier.
# RUN pip install pipenv

# Copy the requirements file into the container
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers
# This step can take some time and increase image size. 
# Consider if all browsers (chromium, firefox, webkit) are needed or just one.
# For this project, chromium is likely sufficient for screenshots.
RUN playwright install chromium --with-deps

# Copy the rest of the application code into the container
COPY . .

# Make entrypoint script executable
RUN chmod +x /app/entrypoint.sh

# Expose the port the app runs on (FastAPI default is 8000, Render will set $PORT)
# EXPOSE 8000 # Render will override this with the PORT env var for the web service

# Set the entrypoint script
ENTRYPOINT ["/app/entrypoint.sh"]

