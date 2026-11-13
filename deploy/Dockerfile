FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .
COPY tests ./tests
COPY scripts ./scripts
RUN useradd --create-home learner && mkdir .local && chown learner:learner .local
USER learner
CMD ["secureflow", "demo"]
