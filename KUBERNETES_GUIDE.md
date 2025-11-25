# Kubernetes Deployment Guide

This guide covers deploying the GraphQL MCP Server to Kubernetes.

## Prerequisites

- Kubernetes cluster (1.19+)
- `kubectl` configured to access your cluster
- Docker image pushed to a container registry
- Basic understanding of Kubernetes concepts

## Quick Start

### 1. Build and Push Docker Image

```bash
# Build the image
docker build -t your-registry/graphql-mcp-server:1.0.0 .

# Push to your registry
docker push your-registry/graphql-mcp-server:1.0.0
```

### 2. Create Kubernetes Resources

```bash
# Apply all manifests
kubectl apply -f k8s/
```

## Kubernetes Manifests

### Namespace

Create a dedicated namespace for the MCP server:

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: graphql-mcp
  labels:
    app: graphql-mcp-server
```

### ConfigMap

Store non-sensitive configuration:

```yaml
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: graphql-mcp-config
  namespace: graphql-mcp
data:
  LOG_LEVEL: "INFO"
  # Add any non-sensitive configuration here
```

### Secret

Store sensitive data like API tokens:

```yaml
# k8s/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: graphql-mcp-secret
  namespace: graphql-mcp
type: Opaque
stringData:
  GRAPHQL_ENDPOINT: "https://your-graphql-api.com/graphql"
  GRAPHQL_AUTH_TOKEN: "your-auth-token-here"
  # For custom headers, use JSON format
  GRAPHQL_HEADERS: '{"X-Custom-Header": "value"}'
```

> ⚠️ **Security Note**: In production, use external secret management like:
> - Kubernetes External Secrets
> - HashiCorp Vault
> - AWS Secrets Manager
> - Azure Key Vault

### Deployment

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: graphql-mcp-server
  namespace: graphql-mcp
  labels:
    app: graphql-mcp-server
spec:
  replicas: 2
  selector:
    matchLabels:
      app: graphql-mcp-server
  template:
    metadata:
      labels:
        app: graphql-mcp-server
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
        - name: graphql-mcp-server
          image: your-registry/graphql-mcp-server:1.0.0
          imagePullPolicy: Always
          ports:
            - name: http
              containerPort: 8000
              protocol: TCP
          envFrom:
            - configMapRef:
                name: graphql-mcp-config
            - secretRef:
                name: graphql-mcp-secret
          resources:
            requests:
              memory: "128Mi"
              cpu: "100m"
            limits:
              memory: "512Mi"
              cpu: "500m"
          livenessProbe:
            httpGet:
              path: /health
              port: http
            initialDelaySeconds: 10
            periodSeconds: 30
            timeoutSeconds: 5
            failureThreshold: 3
          readinessProbe:
            httpGet:
              path: /health
              port: http
            initialDelaySeconds: 5
            periodSeconds: 10
            timeoutSeconds: 3
            failureThreshold: 3
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
      # Optional: Pull secrets for private registries
      # imagePullSecrets:
      #   - name: registry-credentials
```

### Service

```yaml
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: graphql-mcp-server
  namespace: graphql-mcp
  labels:
    app: graphql-mcp-server
spec:
  type: ClusterIP
  ports:
    - port: 80
      targetPort: http
      protocol: TCP
      name: http
  selector:
    app: graphql-mcp-server
```

### Ingress (with TLS)

```yaml
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: graphql-mcp-server
  namespace: graphql-mcp
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
    # Required for SSE connections
    nginx.ingress.kubernetes.io/proxy-buffering: "off"
spec:
  tls:
    - hosts:
        - mcp.your-domain.com
      secretName: graphql-mcp-tls
  rules:
    - host: mcp.your-domain.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: graphql-mcp-server
                port:
                  number: 80
```

### Horizontal Pod Autoscaler

```yaml
# k8s/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: graphql-mcp-server
  namespace: graphql-mcp
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: graphql-mcp-server
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
```

### Pod Disruption Budget

```yaml
# k8s/pdb.yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: graphql-mcp-server
  namespace: graphql-mcp
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: graphql-mcp-server
```

### Network Policy

```yaml
# k8s/networkpolicy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: graphql-mcp-server
  namespace: graphql-mcp
spec:
  podSelector:
    matchLabels:
      app: graphql-mcp-server
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ingress-nginx
      ports:
        - protocol: TCP
          port: 8000
  egress:
    # Allow DNS
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: UDP
          port: 53
    # Allow HTTPS to external GraphQL APIs
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
      ports:
        - protocol: TCP
          port: 443
        - protocol: TCP
          port: 80
```

## Complete Kustomization

Use Kustomize to manage all resources:

```yaml
# k8s/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: graphql-mcp

resources:
  - namespace.yaml
  - configmap.yaml
  - secret.yaml
  - deployment.yaml
  - service.yaml
  - ingress.yaml
  - hpa.yaml
  - pdb.yaml
  - networkpolicy.yaml

commonLabels:
  app.kubernetes.io/name: graphql-mcp-server
  app.kubernetes.io/version: "1.0.0"
  app.kubernetes.io/managed-by: kustomize
```

## Deployment Commands

```bash
# Create namespace first
kubectl create namespace graphql-mcp

# Apply using kustomize
kubectl apply -k k8s/

# Or apply individual files
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secret.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml

# Check deployment status
kubectl -n graphql-mcp get pods
kubectl -n graphql-mcp get svc
kubectl -n graphql-mcp get ingress

# View logs
kubectl -n graphql-mcp logs -l app=graphql-mcp-server -f

# Describe pod for troubleshooting
kubectl -n graphql-mcp describe pod -l app=graphql-mcp-server
```

## Helm Chart (Alternative)

For more advanced deployments, consider creating a Helm chart:

```bash
# Create chart structure
helm create graphql-mcp-server

# Install
helm install graphql-mcp ./graphql-mcp-server \
  --namespace graphql-mcp \
  --create-namespace \
  --set image.repository=your-registry/graphql-mcp-server \
  --set image.tag=1.0.0 \
  --set env.GRAPHQL_ENDPOINT=https://api.example.com/graphql
```

## Cloud-Specific Configurations

### AWS EKS

```yaml
# Use AWS ALB Ingress Controller
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: graphql-mcp-server
  namespace: graphql-mcp
  annotations:
    kubernetes.io/ingress.class: alb
    alb.ingress.kubernetes.io/scheme: internet-facing
    alb.ingress.kubernetes.io/target-type: ip
    alb.ingress.kubernetes.io/certificate-arn: arn:aws:acm:region:account:certificate/xxx
    alb.ingress.kubernetes.io/listen-ports: '[{"HTTPS":443}]'
    alb.ingress.kubernetes.io/ssl-redirect: "443"
spec:
  rules:
    - host: mcp.your-domain.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: graphql-mcp-server
                port:
                  number: 80
```

### Google GKE

```yaml
# Use GKE Ingress
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: graphql-mcp-server
  namespace: graphql-mcp
  annotations:
    kubernetes.io/ingress.class: gce
    kubernetes.io/ingress.global-static-ip-name: graphql-mcp-ip
    networking.gke.io/managed-certificates: graphql-mcp-cert
spec:
  rules:
    - host: mcp.your-domain.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: graphql-mcp-server
                port:
                  number: 80
```

### Azure AKS

```yaml
# Use Azure Application Gateway Ingress
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: graphql-mcp-server
  namespace: graphql-mcp
  annotations:
    kubernetes.io/ingress.class: azure/application-gateway
    appgw.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  tls:
    - hosts:
        - mcp.your-domain.com
      secretName: graphql-mcp-tls
  rules:
    - host: mcp.your-domain.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: graphql-mcp-server
                port:
                  number: 80
```

## Monitoring & Observability

### Prometheus ServiceMonitor

```yaml
# k8s/servicemonitor.yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: graphql-mcp-server
  namespace: graphql-mcp
spec:
  selector:
    matchLabels:
      app: graphql-mcp-server
  endpoints:
    - port: http
      path: /health
      interval: 30s
```

### Health Check Endpoint

The server exposes `/health` for liveness and readiness probes:

```bash
# Test health endpoint
kubectl -n graphql-mcp port-forward svc/graphql-mcp-server 8080:80
curl http://localhost:8080/health
```

## Connecting from VS Code

Once deployed, configure VS Code to connect:

```json
{
  "mcp.servers": {
    "graphql": {
      "type": "http",
      "url": "https://mcp.your-domain.com"
    }
  }
}
```

## Connecting from Claude Desktop

Update Claude Desktop configuration:

```json
{
  "mcpServers": {
    "graphql": {
      "command": "curl",
      "args": ["-N", "https://mcp.your-domain.com/sse"]
    }
  }
}
```

Or use a local proxy that connects to the Kubernetes service.

## Troubleshooting

### Pod Not Starting

```bash
# Check pod status
kubectl -n graphql-mcp get pods

# View pod events
kubectl -n graphql-mcp describe pod <pod-name>

# Check logs
kubectl -n graphql-mcp logs <pod-name>
```

### Connection Issues

```bash
# Test service connectivity from within cluster
kubectl -n graphql-mcp run test --rm -it --image=curlimages/curl -- \
  curl -v http://graphql-mcp-server/health

# Port forward for local testing
kubectl -n graphql-mcp port-forward svc/graphql-mcp-server 8000:80
curl http://localhost:8000/health
```

### SSE Connection Timeouts

Ensure your ingress controller supports long-lived connections:

```yaml
# For nginx-ingress
annotations:
  nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
  nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
  nginx.ingress.kubernetes.io/proxy-buffering: "off"
```

### Secret Not Found

```bash
# Verify secret exists
kubectl -n graphql-mcp get secrets

# Check secret contents (base64 encoded)
kubectl -n graphql-mcp get secret graphql-mcp-secret -o yaml
```

## Security Best Practices

1. **Use Network Policies** to restrict traffic
2. **Enable Pod Security Standards** (restricted)
3. **Use read-only root filesystem**
4. **Run as non-root user**
5. **Rotate secrets regularly**
6. **Enable audit logging**
7. **Use private container registry**
8. **Scan images for vulnerabilities**

## Upgrading

```bash
# Update image tag in deployment
kubectl -n graphql-mcp set image deployment/graphql-mcp-server \
  graphql-mcp-server=your-registry/graphql-mcp-server:1.1.0

# Or use rolling update with new manifest
kubectl apply -f k8s/deployment.yaml

# Check rollout status
kubectl -n graphql-mcp rollout status deployment/graphql-mcp-server

# Rollback if needed
kubectl -n graphql-mcp rollout undo deployment/graphql-mcp-server
```
