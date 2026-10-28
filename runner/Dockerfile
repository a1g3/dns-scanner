FROM dhi.io/python:3.14-debian-dev AS builder

WORKDIR /app

RUN pip install --no-cache-dir pipenv

COPY ./runner/Pipfile ./runner/Pipfile.lock ./

ENV PIPENV_VENV_IN_PROJECT=1

RUN pipenv install --deploy



FROM dhi.io/python:3.14-debian

WORKDIR /app

COPY --from=builder /app/.venv /app/.venv
COPY ./runner/main.py .

ENV PYTHONUNBUFFERED=1
ENV PATH="/app/.venv/bin:$PATH"

CMD ["python", "main.py"]
