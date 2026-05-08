FROM python:3.11-slim
RUN apt-get update && apt-get install -y nmap nikto git curl openssh-client ansible gobuster && \
    git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl && \
    chmod +x /opt/testssl/testssl.sh

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0"]