# How to Run: Enterprise GenAI Security Gateway

This guide covers local simulation, test execution, containerization, and AWS Terraform deployment.

---

## 1. Local CLI Threat Simulation

Run the automated simulation demonstrating live prompt screening, PII redaction, and SHA-256 manifest generation:

```bash
# Windows PowerShell
.\run.ps1

# Windows Command Prompt
run.bat

# Linux / macOS
chmod +x run.sh && ./run.sh
```

Or execute directly with Python:
```bash
python -m src.cli simulate
```

---

## 2. Running Automated Unit Tests & Linting

```bash
# Execute Pytest suite
pytest -v

# Format and lint codebase
ruff check --fix src tests
ruff format src tests
```

---

## 3. Docker Container Deployment

Build and run the containerized GenAI Gateway reverse proxy locally:

```bash
# Build Docker image
docker build -t genai-security-gateway:latest .

# Run container and execute simulation
docker run --rm genai-security-gateway:latest
```

---

## 4. Terraform Cloud Deployment on AWS

Deploy the complete infrastructure stack into your AWS account:

```bash
cd terraform

# Initialize Terraform
terraform init

# Review execution plan
terraform plan

# Apply infrastructure
terraform apply -auto-approve
```

To destroy provisioned resources:
```bash
terraform destroy -auto-approve
```
