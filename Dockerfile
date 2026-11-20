FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -m lab && chown -R lab /app
USER lab
CMD ["sh", "-c", "python3 simulator.py && python3 main.py data/simulated.jsonl && python3 attack_coverage.py"]
