FROM python:3.13-slim
WORKDIR /app
COPY requirements-browser.txt .
RUN pip install --no-cache-dir -r requirements-browser.txt && python -m playwright install --with-deps chromium
COPY app ./app
CMD ["python","-m","app.page_analyzer_worker"]