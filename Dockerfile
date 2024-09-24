FROM python:3.8-slim
RUN python -m pip install --upgrade pip

WORKDIR /app
COPY ./requirements.txt /app/requirements.txt
RUN pip3 install -r requirements.txt

ENV FLASK_APP='main.py'
ENV FLASK_DEBUG=1
ENV PYTHONPATH=/app:/app/docs_processing