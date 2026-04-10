FROM python:3.10-slim

WORKDIR /app

# Install dependencies first (better caching)
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Copy only required files
COPY . .

CMD ["python", "app.py"]
