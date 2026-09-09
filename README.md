# 🛡️ SecureFileGuard — Serverless File Security & Threat Detection

**SecureFileGuard** is a serverless cloud security platform built on AWS that automatically analyzes uploaded files, identifies potentially malicious or suspicious content, quarantines threats, records scan results, and sends real-time security alerts.

The platform combines **AWS Lambda, Amazon S3, SQS, DynamoDB, SNS, Amazon ECR, Docker, and ClamAV**, with additional heuristic analysis for detecting suspicious executable characteristics.

Infrastructure is managed using **Terraform**, making the entire security environment reproducible through Infrastructure as Code

---

##  Project Objective

The goal of SecureFileGuard is to demonstrate how a modern cloud-based file security system can automatically:

1. Receive uploaded files securely.
2. Analyze files for suspicious characteristics.
3. Scan files using ClamAV.
4. Calculate a threat score.
5. Separate clean files from suspicious files.
6. Quarantine potentially dangerous files.
7. Store security scan results for auditing.
8. Send automated security alerts.
9. Provide a dashboard for monitoring scan statistics.

---

#  Architecture
<img width="1408" height="768" alt="2" src="https://github.com/user-attachments/assets/ed0d80d2-f8c6-4aaa-9321-76a457b77dec" />
                    
```
```

#  Security Monitoring Dashboard

SecureFileGuard includes a web-based monitoring dashboard for viewing file security statistics.

The dashboard retrieves scan results from DynamoDB through a serverless API.

### Dashboard provides:

* Total files scanned
* Clean files
* Suspicious files
* Quarantined files
* Average threat score
* Security scan statistics

```text
Dashboard
    │
    ▼
API Gateway
    │
    ▼
Dashboard Lambda
    │
    ▼
DynamoDB
```

### Dashboard Screenshots

<img width="1590" height="450" alt="01-security-consloe log" src="https://github.com/user-attachments/assets/f2c7ccf3-68d1-4a15-9840-d02a66528464" />
<img width="1870" height="829" alt="01-security-dashboard1" src="https://github.com/user-attachments/assets/8c331100-5bad-4ed7-a88f-02f2adea005f" />
<img width="1849" height="826" alt="01-security-dashboard2" src="https://github.com/user-attachments/assets/1ffc6e34-f07a-4273-b942-08a7ddd8eb93" />


### Dashboard API

The statistics can also be retrieved directly through the API:


Example response:

```text
total_files          : 9
clean                : 6
suspicious           : 0
quarantined          : 3
average_threat_score : 30
```


#  Security Detection Pipeline

When a file is uploaded, SecureFileGuard performs multiple security checks.

### 1. File Hashing

A **SHA-256 hash** is generated for each scanned file.

This provides a unique fingerprint that can be used for:

* File identification
* Audit records
* Investigation
* Comparing repeated uploads

### 2. Extension Analysis

The scanner checks the file extension for potentially dangerous types such as:

```text
.exe
.dll
.bat
.cmd
.ps1
.vbs
.js
```

### 3. File Signature / Magic Byte Analysis

The scanner analyzes the actual file signature rather than relying only on the filename.
For example, a Windows executable can be identified through the **PE/MZ executable signature**.
This helps detect files that may have been renamed to disguise their real type.

### 4. Entropy Analysis

File entropy is analyzed to identify characteristics commonly associated with packed, compressed, or potentially obfuscated content.


### 5. ClamAV Antivirus Scanning

The scanner also integrates **ClamAV** for signature-based malware detection.

```text
Docker
   │
   ▼
ClamAV Scanner
   │
   ▼
Amazon ECR
   │
   ▼
Lambda Container Image
```

ClamAV provides an additional antivirus detection layer alongside the custom heuristic analysis.

---

#  Containerized ClamAV Integration

Instead of running the scanner as a traditional Lambda ZIP package, the security scanner is deployed as a **Docker container image**.

The image contains:

* Python scanner
* ClamAV
* ClamAV virus database
* Required runtime dependencies

The container image is stored in **Amazon ECR** and deployed to AWS Lambda.
This approach makes it possible to package security software and its dependencies consistently across development and AWS environments.

### Local Docker Validation

The ClamAV environment was first tested locally using Docker.

ClamAV was also tested against the harmless **EICAR antivirus test signature** to verify that the antivirus engine was functioning correctly.

> EICAR is a standard harmless test file used to verify antivirus detection. It is not real malware.

### Containerized Scanner Screenshots
docker-clamav-container.png
<img width="1602" height="910" alt="03-docker-clamav-container png" src="https://github.com/user-attachments/assets/0e6b2068-f1da-4260-95af-95af08833db1" />
container-lambda
<img width="1888" height="584" alt="02-container-lambda" src="https://github.com/user-attachments/assets/55a9eec9-4c90-4413-bcca-a7f82ccea632" />
ecr-clamav-scanner
<img width="1905" height="499" alt="03-ecr-clamav-scanner" src="https://github.com/user-attachments/assets/1b032750-1cfa-4eb4-a7b0-2e61fa5b8e4b" />


---

#  Threat Detection & Quarantine

The scan result was also stored in DynamoDB and an SNS security alert was generated.

### Threat Detection Evidence
threat-detection-cloudwatch
<img width="1907" height="582" alt="04-threat-detection-cloudwatch" src="https://github.com/user-attachments/assets/bed5b276-7db4-4955-a38c-e8931717b7bb" />
threat-quarantine
<img width="1907" height="573" alt="05-threat-quarantine" src="https://github.com/user-attachments/assets/725a2449-acc6-42d7-9a43-87ce88a47cdd" />
dynamodb-audit
<img width="1876" height="808" alt="06-dynamodb-audit" src="https://github.com/user-attachments/assets/66eeff1f-7e11-4884-b919-81a91a0f0013" />
sns-security-alert
<img width="1486" height="520" alt="07-sns-security-alert" src="https://github.com/user-attachments/assets/4f4be1c0-69fe-4a1b-85d7-3b955160baf9" />

---

# 📧 Real-Time Security Alerts

When a suspicious file is quarantined, the scanner publishes a security event to an **Amazon SNS topic**.

The notification contains information such as:

```json
{
  "file": "uploads/security-integration-test.exe",
  "status": "QUARANTINED",
  "threat_score": 90,
  "sha256": "4b20121be423677ea731fe21bb10917d4e151165f204e6ed99bc0b76e6f33a5b",
  "clamav_status": "CLEAN"
}
```

This provides immediate visibility when a potentially dangerous file is detected.

---

### Antivirus Test

The ClamAV engine was independently tested with the harmless EICAR test signature.

This verified that the ClamAV engine and virus database were functioning correctly.

---

---

# 📁 Project Structure

```text
SecureFileGuard/
│
├── terraform/
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   ├── iam.tf
│   ├── s3.tf
│   ├── sqs.tf
│   ├── dynamodb.tf
│   ├── sns.tf
│   ├── lambda.tf
│   └── api_gateway.tf
│
├── lambda/
│   ├── upload/
│   │   └── lambda_function.py
│   │
│   └── scanner/
│       ├── lambda_function.py
│       └── clamav/
│           ├── Dockerfile
│           ├── lambda_function.py
│           └── clamav-db/
│
├── dashboard/
│   ├── api/
│   │   └── lambda_function.py
│   │
│   └── frontend/
│
├── test/
│   ├── clean.txt
│   ├── synthetic.exe
│   └── alert-test.exe
│
├── docs/
│   └── screenshots/
│
└── README.md
```

---


# Author
 Udeesha Jayendra
