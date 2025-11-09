# backend/Dockerfile
FROM python:3.11-slim

WORKDIR /app

# системні залежності (додати sqlite3 та інструменти, якщо треба)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Зкопіюємо тільки requirements спочатку для кешування шарів
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Копіюємо код та sql-ініціалізацію
COPY app /app/app
COPY db_init.sql /app/db_init.sql
COPY init_db.sh /app/init_db.sh
RUN chmod +x /app/init_db.sh

ENV PYTHONPATH=/app
EXPOSE 8000

ENTRYPOINT ["/app/init_db.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]