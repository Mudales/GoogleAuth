FROM python:3.12-alpine

RUN apk add --no-cache zbar-dev

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY bot.py migration_pb2.py ./

CMD ["python", "bot.py"]
