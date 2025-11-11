# Guía de Deployment de MIESC

Documentación completa para desplegar MIESC en diferentes entornos.

---

## 📋 Tabla de Contenidos

- [Instalación Local](#instalación-local)
- [Deployment en Servidor](#deployment-en-servidor)
- [Docker Deployment](#docker-deployment)
- [CI/CD Integration](#cicd-integration)
- [Producción](#producción)

---

## Instalación Local

### Prerrequisitos

**Software Requerido**:
- Python 3.10+ ([python.org](https://www.python.org/))
- Git ([git-scm.com](https://git-scm.com/))
- Node.js 18+ ([nodejs.org](https://nodejs.org/)) - Para Solhint/Surya
- Foundry ([getfoundry.sh](https://getfoundry.sh/)) - Para Foundry Fuzz

**Opcional** (para auditorías completas):
- Slither (`pip install slither-analyzer`)
- Mythril (`pip install mythril`)
- Echidna ([github.com/crytic/echidna](https://github.com/crytic/echidna))
- Certora Prover (requiere licencia)

---

### Instalación Paso a Paso

#### 1. Clonar Repositorio

```bash
git clone https://github.com/fboiero/MIESC.git
cd xaudit
```

#### 2. Crear Entorno Virtual

```bash
# Crear venv
python -m venv venv

# Activar
# macOS/Linux:
source venv/bin/activate

# Windows:
venv\Scripts\activate
```

#### 3. Instalar Dependencias Python

```bash
# Dependencias core
pip install -r requirements.txt

# Dependencias completas (incluye todas las herramientas)
pip install -r requirements_full.txt
```

#### 4. Instalar Herramientas de Análisis

**Slither** (Static Analysis):
```bash
pip install slither-analyzer
solc-select install 0.8.0
solc-select use 0.8.0
```

**Solhint** (Linting):
```bash
npm install -g solhint
```

**Surya** (Visualization):
```bash
npm install -g surya
```

**Foundry** (Fuzzing):
```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

**Mythril** (Symbolic Execution - Opcional):
```bash
pip install mythril
```

**Echidna** (Property Fuzzing - Opcional):
```bash
# macOS
brew install echidna

# Linux
wget https://github.com/crytic/echidna/releases/latest/download/echidna-linux-x86_64.tar.gz
tar -xzf echidna-linux-x86_64.tar.gz
sudo mv echidna /usr/local/bin/
```

#### 5. Configurar Variables de Entorno

```bash
# Crear .env
cat > .env <<EOF
# OpenAI API Key (para AIAgent)
OPENAI_API_KEY=sk-...

# Configuración opcional
SLITHER_PATH=/usr/local/bin/slither
MYTHRIL_PATH=/usr/local/bin/myth
ECHIDNA_PATH=/usr/local/bin/echidna

# Output directories
OUTPUT_DIR=outputs
EVIDENCE_DIR=outputs/evidence
REPORTS_DIR=outputs/reports
EOF
```

#### 6. Verificar Instalación

```bash
# Test básico
python -c "
from agents.static_agent import StaticAgent
agent = StaticAgent()
print('✅ StaticAgent initialized')
"

# Test herramientas
slither --version
solhint --version
forge --version
```

#### 7. Ejecutar Tests

```bash
# Tests end-to-end
python test_mcp_e2e.py

# Demo POC
python demo_mcp_poc.py examples/voting.sol
```

---

## Deployment en Servidor

### Deployment en Linux Server

#### 1. Preparar Servidor

```bash
# Actualizar sistema
sudo apt update && sudo apt upgrade -y

# Instalar dependencias sistema
sudo apt install -y python3.10 python3-pip git nodejs npm build-essential

# Instalar Rust (para Echidna)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

#### 2. Clonar y Setup

```bash
# Como usuario no-root
cd /opt
sudo git clone https://github.com/fboiero/MIESC.git
sudo chown -R $USER:$USER xaudit
cd xaudit

# Setup venv
python3.10 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### 3. Instalar Herramientas

```bash
# Slither + solc
pip install slither-analyzer solc-select
solc-select install 0.8.0
solc-select use 0.8.0

# Node tools
npm install -g solhint surya

# Foundry
curl -L https://foundry.paradigm.xyz | bash
source ~/.bashrc
foundryup
```

#### 4. Configurar como Servicio Systemd

Crear `/etc/systemd/system/miesc-mcp.service`:

```ini
[Unit]
Description=MIESC MCP Server
After=network.target

[Service]
Type=simple
User=miesc
WorkingDirectory=/opt/xaudit
Environment="PATH=/opt/xaudit/venv/bin:/usr/local/bin:/usr/bin"
Environment="PYTHONPATH=/opt/xaudit"
ExecStart=/opt/xaudit/venv/bin/python /opt/xaudit/mcp_server.py --stdio
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Habilitar y arrancar**:
```bash
sudo systemctl daemon-reload
sudo systemctl enable miesc-mcp
sudo systemctl start miesc-mcp

# Ver status
sudo systemctl status miesc-mcp

# Ver logs
sudo journalctl -u miesc-mcp -f
```

#### 5. Configurar Nginx (Proxy Reverso - Opcional)

Si necesitas exponer vía HTTP:

```nginx
# /etc/nginx/sites-available/miesc
server {
    listen 80;
    server_name miesc.example.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/miesc /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

---

## Docker Deployment

### Dockerfile

Crear `Dockerfile`:

```dockerfile
FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    nodejs \
    npm \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Foundry
RUN curl -L https://foundry.paradigm.xyz | bash && \
    ~/.foundry/bin/foundryup

ENV PATH="/root/.foundry/bin:${PATH}"

# Set working directory
WORKDIR /app

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install analysis tools
RUN pip install slither-analyzer solc-select && \
    npm install -g solhint surya

# Setup Solidity compiler
RUN solc-select install 0.8.0 && \
    solc-select use 0.8.0

# Copy application
COPY . .

# Create output directories
RUN mkdir -p outputs/evidence outputs/reports outputs/metrics

# Expose port (if needed)
EXPOSE 3000

# Default command
CMD ["python", "mcp_server.py", "--stdio"]
```

### docker-compose.yml

```yaml
version: '3.8'

services:
  miesc:
    build: .
    image: miesc:latest
    container_name: miesc-server
    restart: unless-stopped
    volumes:
      - ./examples:/app/examples
      - ./outputs:/app/outputs
      - ./contracts:/app/contracts  # Mount your contracts
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - PYTHONPATH=/app
    stdin_open: true
    tty: true
    command: python mcp_server.py --stdio

  miesc-dashboard:
    image: nginx:alpine
    container_name: miesc-dashboard
    restart: unless-stopped
    ports:
      - "8080:80"
    volumes:
      - ./src/dashboard:/usr/share/nginx/html:ro
```

### Build y Run

```bash
# Build image
docker build -t miesc:latest .

# Run con docker-compose
docker-compose up -d

# Ver logs
docker-compose logs -f miesc

# Test
docker exec -it miesc-server python test_mcp_e2e.py
```

### Kubernetes Deployment (Opcional)

Crear `k8s/deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: miesc-server
  labels:
    app: miesc
spec:
  replicas: 2
  selector:
    matchLabels:
      app: miesc
  template:
    metadata:
      labels:
        app: miesc
    spec:
      containers:
      - name: miesc
        image: miesc:latest
        ports:
        - containerPort: 3000
        env:
        - name: OPENAI_API_KEY
          valueFrom:
            secretKeyRef:
              name: miesc-secrets
              key: openai-api-key
        volumeMounts:
        - name: contracts
          mountPath: /app/contracts
        - name: outputs
          mountPath: /app/outputs
      volumes:
      - name: contracts
        persistentVolumeClaim:
          claimName: miesc-contracts-pvc
      - name: outputs
        persistentVolumeClaim:
          claimName: miesc-outputs-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: miesc-service
spec:
  selector:
    app: miesc
  ports:
    - protocol: TCP
      port: 3000
      targetPort: 3000
  type: LoadBalancer
```

```bash
# Deploy
kubectl apply -f k8s/deployment.yaml

# Ver pods
kubectl get pods -l app=miesc

# Ver logs
kubectl logs -l app=miesc -f
```

---

## CI/CD Integration

### GitHub Actions

El workflow ya está configurado en `.github/workflows/miesc_audit.yml`.

**Personalización adicional**:

```yaml
# .github/workflows/deploy.yml
name: Deploy MIESC

on:
  push:
    branches: [ main ]
    tags: [ 'v*' ]

jobs:
  build-and-push:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build Docker image
        run: docker build -t ghcr.io/${{ github.repository }}:${{ github.sha }} .

      - name: Push to GitHub Container Registry
        run: |
          echo ${{ secrets.GITHUB_TOKEN }} | docker login ghcr.io -u ${{ github.actor }} --password-stdin
          docker push ghcr.io/${{ github.repository }}:${{ github.sha }}

  deploy-to-server:
    needs: build-and-push
    runs-on: ubuntu-latest
    steps:
      - name: Deploy via SSH
        uses: appleboy/ssh-action@master
        with:
          host: ${{ secrets.SERVER_HOST }}
          username: ${{ secrets.SERVER_USER }}
          key: ${{ secrets.SSH_PRIVATE_KEY }}
          script: |
            cd /opt/xaudit
            git pull
            docker-compose pull
            docker-compose up -d
```

### GitLab CI

Crear `.gitlab-ci.yml`:

```yaml
stages:
  - test
  - build
  - deploy

test:
  stage: test
  image: python:3.10
  script:
    - pip install -r requirements.txt
    - python test_mcp_e2e.py
  only:
    - merge_requests
    - main

build:
  stage: build
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  only:
    - main

deploy:
  stage: deploy
  script:
    - ssh user@server "cd /opt/xaudit && docker-compose pull && docker-compose up -d"
  only:
    - main
```

---

## Producción

### Checklist Pre-Producción

**Seguridad**:
- [ ] API keys en secrets manager (no en .env)
- [ ] HTTPS habilitado
- [ ] Rate limiting configurado
- [ ] Logs auditados

**Performance**:
- [ ] Timeouts apropiados
- [ ] Resource limits (CPU/RAM)
- [ ] Caching habilitado
- [ ] Load balancing si es necesario

**Monitoring**:
- [ ] Logs centralizados (ELK, Splunk)
- [ ] Métricas (Prometheus, Grafana)
- [ ] Alertas configuradas
- [ ] Health checks

**Backup**:
- [ ] Audit trails backed up
- [ ] Contracts versionados
- [ ] Outputs preservados

### Secrets Management

**Usar Vault, AWS Secrets Manager, o similar**:

```python
# config.py
import os
from typing import Optional

def get_secret(key: str) -> Optional[str]:
    """Get secret from environment or secrets manager"""
    # Try environment first
    value = os.getenv(key)
    if value:
        return value

    # Try AWS Secrets Manager
    try:
        import boto3
        client = boto3.client('secretsmanager')
        response = client.get_secret_value(SecretId=f'miesc/{key}')
        return response['SecretString']
    except:
        return None

# Usage
OPENAI_API_KEY = get_secret('OPENAI_API_KEY')
```

### Monitoring

**Prometheus Metrics**:

```python
# Add to mcp_server.py
from prometheus_client import Counter, Histogram, start_http_server

# Metrics
audit_counter = Counter('miesc_audits_total', 'Total audits')
audit_duration = Histogram('miesc_audit_duration_seconds', 'Audit duration')

def handle_tool_call(tool_name, arguments):
    with audit_duration.time():
        audit_counter.inc()
        # ... existing code
```

**Start metrics server**:
```python
# In main()
start_http_server(9090)  # Prometheus metrics on :9090
```

### Health Checks

```python
# health_check.py
def health_check():
    """Check if all components are healthy"""
    checks = {
        "context_bus": check_context_bus(),
        "agents": check_agents(),
        "tools": check_tools()
    }
    return all(checks.values()), checks

def check_context_bus():
    try:
        bus = get_context_bus()
        stats = bus.get_stats()
        return True
    except:
        return False
```

### Logging

**Structured logging**:

```python
import structlog

logger = structlog.get_logger()

logger.info("audit_started",
    contract=contract_path,
    priority=priority,
    user=user_id
)
```

---

## Deployment Scenarios

### Scenario 1: Academic Research

**Requerimientos**:
- Laptop/Desktop local
- No alta disponibilidad necesaria

**Setup Recomendado**:
- Instalación local
- Cliente: 5ire o AIQL TUUI
- Outputs guardados para tesis

---

### Scenario 2: Startup/Empresa Pequeña

**Requerimientos**:
- Múltiples usuarios
- CI/CD integration
- Disponibilidad 95%

**Setup Recomendado**:
- Docker en VPS (DigitalOcean, AWS EC2)
- GitHub Actions CI/CD
- Backup diario de outputs
- Monitoring básico

---

### Scenario 3: Enterprise

**Requerimientos**:
- Alta disponibilidad 99.9%
- Escalabilidad
- Compliance (SOC2, ISO 27001)
- Multi-tenant

**Setup Recomendado**:
- Kubernetes cluster
- Load balancing
- Secrets manager
- Full monitoring stack
- Disaster recovery

---

## Troubleshooting

### Problema: Slither no encuentra contratos

```bash
# Verificar path
which slither

# Reinstalar
pip uninstall slither-analyzer
pip install slither-analyzer

# Verificar solc
solc-select use 0.8.0
```

### Problema: MCP Server no responde

```bash
# Ver logs
python mcp_server.py --stdio 2>&1 | tee mcp.log

# Test directo
echo '{"jsonrpc":"2.0","id":1,"method":"initialize"}' | python mcp_server.py --stdio
```

### Problema: Docker build falla

```bash
# Build con logs verbose
docker build --progress=plain -t miesc:latest .

# Limpiar cache
docker builder prune

# Rebuild sin cache
docker build --no-cache -t miesc:latest .
```

---

## Referencias

- [Docker Docs](https://docs.docker.com/)
- [Kubernetes Docs](https://kubernetes.io/docs/)
- [GitHub Actions](https://docs.github.com/actions)
- [Prometheus](https://prometheus.io/docs/)
- [MCP Protocol](https://modelcontextprotocol.io/)

---

**Última Actualización**: Octubre 2025
**Mantenedor**: Fernando Boiero (fboiero@frvm.utn.edu.ar)
