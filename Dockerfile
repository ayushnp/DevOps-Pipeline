# DevOps-Pipeline-main/Dockerfile update
FROM python:3.10.14-slim-bookworm 

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "app.py"]