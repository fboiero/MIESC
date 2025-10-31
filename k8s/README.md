# MIESC Kubernetes Deployment

## Overview

Production-ready Kubernetes deployment for MIESC framework with:
- **Horizontal autoscaling** (2-10 pods based on CPU/memory)
- **High availability** (multiple replicas, rolling updates)
- **Persistent storage** (outputs, contracts)
- **Redis caching** (for result persistence)
- **Ingress** (HTTPS with Let's Encrypt)
- **Security** (non-root containers, resource limits, secrets)

## Architecture

```
                    ┌──────────────┐
                    │   Ingress    │
                    │ (HTTPS/TLS)  │
                    └──────┬───────┘
                           │
                ┌──────────▼──────────┐
                │  Load Balancer Svc  │
                └──────────┬──────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
    ┌───▼────┐        ┌───▼────┐        ┌───▼────┐
    │ MIESC  │        │ MIESC  │        │ MIESC  │
    │ Pod 1  │        │ Pod 2  │        │ Pod 3  │
    └───┬────┘        └───┬────┘        └───┬────┘
        │                  │                  │
        └──────────────────┼──────────────────┘
                           │
                    ┌──────▼───────┐
                    │  Redis Cache │
                    └──────────────┘
```

## Quick Start

### 1. Prerequisites

```bash
# Verify kubectl is installed and configured
kubectl version --client

# Verify cluster access
kubectl cluster-info

# Install NGINX Ingress Controller (if not present)
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.8.1/deploy/static/provider/cloud/deploy.yaml
```

### 2. Create Namespace

```bash
kubectl apply -f k8s/namespace.yaml
```

### 3. Create Secrets

**IMPORTANT**: Never commit actual secrets to Git!

```bash
# Create secrets for API keys
kubectl create secret generic miesc-secrets \
  --from-literal=openai-api-key=sk-your-openai-key-here \
  --from-literal=anthropic-api-key=sk-ant-your-anthropic-key-here \
  -n miesc

# Verify secret created
kubectl get secrets -n miesc
```

### 4. Deploy Redis

```bash
kubectl apply -f k8s/redis-deployment.yaml

# Wait for Redis to be ready
kubectl wait --for=condition=ready pod -l app=redis -n miesc --timeout=120s

# Verify Redis is running
kubectl get pods -n miesc -l app=redis
```

### 5. Deploy ConfigMap

```bash
kubectl apply -f k8s/configmap.yaml
```

### 6. Deploy MIESC

```bash
kubectl apply -f k8s/miesc-deployment.yaml

# Wait for deployment to be ready
kubectl rollout status deployment/miesc-analyzer -n miesc

# Verify pods are running
kubectl get pods -n miesc -l app=miesc
```

### 7. Deploy Autoscaler

```bash
kubectl apply -f k8s/hpa.yaml

# Verify HPA is configured
kubectl get hpa -n miesc
```

### 8. Deploy Ingress (Optional)

```bash
# Edit k8s/ingress.yaml to set your domain
# Replace "miesc.example.com" with your actual domain

kubectl apply -f k8s/ingress.yaml

# Get ingress IP
kubectl get ingress -n miesc
```

## Deployment Verification

### Check All Resources

```bash
# All resources in miesc namespace
kubectl get all -n miesc

# Detailed status
kubectl get pods,svc,pvc,hpa -n miesc -o wide
```

### Check Logs

```bash
# MIESC pod logs
kubectl logs -f deployment/miesc-analyzer -n miesc

# Redis logs
kubectl logs -f deployment/redis -n miesc

# All pods
kubectl logs -f -l app=miesc -n miesc
```

### Check Events

```bash
kubectl get events -n miesc --sort-by='.lastTimestamp'
```

## Usage

### Run Analysis

```bash
# Get pod name
POD=$(kubectl get pod -n miesc -l app=miesc -o jsonpath='{.items[0].metadata.name}')

# Execute analysis
kubectl exec -it $POD -n miesc -- \
  python3 main.py --target examples/reentrancy.sol

# Copy results out
kubectl cp miesc/$POD:/app/outputs/report.pdf ./report.pdf
```

### Access MCP Server

```bash
# Port forward to local machine
kubectl port-forward -n miesc svc/miesc-service 8080:8080

# Access at http://localhost:8080
```

### Interactive Shell

```bash
# Get shell in pod
kubectl exec -it $POD -n miesc -- /bin/bash

# Inside pod:
miesc@pod:/app$ python3 main.py --target examples/reentrancy.sol
miesc@pod:/app$ python3 -m pytest tests/
```

## Monitoring

### Check Resource Usage

```bash
# CPU and memory usage
kubectl top pods -n miesc

# Node usage
kubectl top nodes
```

### View Metrics

```bash
# Port forward Prometheus metrics
kubectl port-forward -n miesc svc/miesc-service 9090:9090

# Access metrics at http://localhost:9090/metrics
```

### HPA Status

```bash
# Watch autoscaler
kubectl get hpa -n miesc -w

# Detailed HPA status
kubectl describe hpa miesc-hpa -n miesc
```

## Configuration

### Update ConfigMap

```bash
# Edit configmap
kubectl edit configmap miesc-config -n miesc

# Or apply updated file
kubectl apply -f k8s/configmap.yaml

# Restart pods to pick up changes
kubectl rollout restart deployment/miesc-analyzer -n miesc
```

### Update Secrets

```bash
# Update API key
kubectl create secret generic miesc-secrets \
  --from-literal=openai-api-key=sk-new-key \
  --dry-run=client -o yaml | kubectl apply -n miesc -f -

# Restart pods
kubectl rollout restart deployment/miesc-analyzer -n miesc
```

### Scale Manually

```bash
# Scale to 5 replicas
kubectl scale deployment/miesc-analyzer --replicas=5 -n miesc

# Verify
kubectl get pods -n miesc -l app=miesc
```

## Maintenance

### Update Image

```bash
# Update to new version
kubectl set image deployment/miesc-analyzer \
  miesc=miesc:2.3.0 -n miesc

# Watch rollout
kubectl rollout status deployment/miesc-analyzer -n miesc

# Rollback if needed
kubectl rollout undo deployment/miesc-analyzer -n miesc
```

### Backup Persistent Data

```bash
# Backup outputs
kubectl exec deployment/miesc-analyzer -n miesc -- \
  tar czf /tmp/outputs-backup.tar.gz /app/outputs

kubectl cp miesc/$POD:/tmp/outputs-backup.tar.gz ./outputs-backup.tar.gz

# Backup Redis data
kubectl exec deployment/redis -n miesc -- \
  redis-cli SAVE

kubectl cp miesc/redis-pod:/data/dump.rdb ./redis-backup.rdb
```

### Clean Up

```bash
# Delete everything in namespace
kubectl delete namespace miesc

# Or delete individual resources
kubectl delete -f k8s/miesc-deployment.yaml
kubectl delete -f k8s/redis-deployment.yaml
kubectl delete -f k8s/hpa.yaml
kubectl delete -f k8s/ingress.yaml
kubectl delete -f k8s/configmap.yaml
kubectl delete secret miesc-secrets -n miesc
kubectl delete -f k8s/namespace.yaml
```

## Troubleshooting

### Pods Not Starting

```bash
# Describe pod to see events
kubectl describe pod $POD -n miesc

# Check logs
kubectl logs $POD -n miesc

# Check previous logs (if crashed)
kubectl logs $POD -n miesc --previous
```

### Image Pull Errors

```bash
# If using private registry, create imagePullSecret
kubectl create secret docker-registry regcred \
  --docker-server=registry.example.com \
  --docker-username=user \
  --docker-password=pass \
  -n miesc

# Add to deployment spec.template.spec.imagePullSecrets
```

### Resource Limits

```bash
# If pods are OOMKilled or throttled
kubectl describe pod $POD -n miesc

# Increase limits in miesc-deployment.yaml
resources:
  limits:
    memory: "8Gi"  # Increase from 4Gi
    cpu: "4000m"   # Increase from 2000m
```

### Redis Connection Issues

```bash
# Test Redis connectivity from MIESC pod
kubectl exec -it $POD -n miesc -- \
  python3 -c "import redis; r=redis.Redis(host='redis', port=6379); print(r.ping())"

# Expected output: True

# Check Redis service
kubectl get svc redis -n miesc
kubectl describe svc redis -n miesc
```

### HPA Not Scaling

```bash
# Check metrics server is installed
kubectl get deployment metrics-server -n kube-system

# Install if missing
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml

# Verify HPA can read metrics
kubectl describe hpa miesc-hpa -n miesc
```

## Production Checklist

Before deploying to production:

- [ ] **Secrets**: Use proper secret management (Vault, Sealed Secrets, etc.)
- [ ] **Resource limits**: Set appropriate CPU/memory limits based on load testing
- [ ] **Storage**: Use appropriate StorageClass (SSD for performance)
- [ ] **Backup**: Set up automated backups for PVCs
- [ ] **Monitoring**: Deploy Prometheus + Grafana for observability
- [ ] **Logging**: Configure log aggregation (ELK, Loki, etc.)
- [ ] **Network policies**: Restrict pod-to-pod communication
- [ ] **Pod security**: Enable Pod Security Standards
- [ ] **RBAC**: Configure appropriate service accounts and roles
- [ ] **Ingress**: Configure proper TLS certificates (Let's Encrypt)
- [ ] **Rate limiting**: Configure appropriate limits in Ingress
- [ ] **Cost management**: Set up budget alerts
- [ ] **Disaster recovery**: Document and test recovery procedures

## Security Hardening

### Network Policies

```yaml
# Restrict Redis access
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: redis-policy
  namespace: miesc
spec:
  podSelector:
    matchLabels:
      app: redis
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: miesc
    ports:
    - protocol: TCP
      port: 6379
```

### Pod Security

```yaml
# Add to deployment spec.template.spec
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 1000
  seccompProfile:
    type: RuntimeDefault
  capabilities:
    drop:
    - ALL
```

## Support

For issues or questions:
- GitHub Issues: https://github.com/fboiero/xaudit/issues
- Email: fboiero@frvm.utn.edu.ar
- Documentation: https://github.com/fboiero/xaudit/tree/main/docs

## License

GPL-3.0 (same as MIESC framework)
