# SecureFileGuard

## Serverless File Security & Threat Detection

SecureFileGuard is an AWS serverless platform that analyzes uploaded files, detects suspicious files, quarantines threats, stores scan results, and sends security alerts.

## Security Dashboard — Updated

The latest update adds a **React security monitoring dashboard** connected to AWS through API Gateway, Lambda, and DynamoDB.
<img width="1866" height="815" alt="26-security-dashboard1" src="https://github.com/user-attachments/assets/724fa7ae-ff6d-480a-b19b-0ae45b91fb7f" />
<img width="1831" height="684" alt="26-security-dashboard2" src="https://github.com/user-attachments/assets/108cc28e-8b5e-4484-a7e4-f9daf5ba55ad" />

### Dashboard Features

* Total, clean, suspicious & quarantined files
* Average threat score
* Threat distribution chart
* Detection & quarantine rates
* Recent scan history
* SHA-256 and scan timestamps

### Architecture

```text
React Dashboard
      ↓
API Gateway
      ↓
Dashboard Lambda
      ↓
DynamoDB
```

### AWS Services

**S3 · Lambda · SQS · DynamoDB · SNS · API Gateway · CloudWatch · IAM · Terraform**

### Security Features

* SHA-256 hashing
* File signature & extension analysis
* Entropy analysis
* Threat scoring
* Automatic quarantine
* SNS security alerts
* SQS retry & DLQ
* IAM least privilege
* S3 encryption & Block Public Access
* Path traversal & file-size protection

### Run Dashboard

```bash
cd dashboard/frontend
npm install
npm start
```

### Infrastructure

```bash
cd terraform
terraform init
terraform apply
```

## Author

**Udeesha Jayendra**
