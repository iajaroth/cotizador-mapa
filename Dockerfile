FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir flask staticmap Pillow
COPY app.py .
COPY templates/ templates/
RUN mkdir -p /app/data/mapas
ENV PORT=5050
HEALTHCHECK --interval=30s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5050/health')"
CMD ["python", "app.py"]