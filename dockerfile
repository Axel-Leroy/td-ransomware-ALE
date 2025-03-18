FROM python:3.9.21-slim-bullseye

RUN apt update && apt install -y python3-pip
RUN pip3 install cryptography requests