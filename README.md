Evidence-Based Evaluation of Automated Cloud Security Controls

## Overview

This repository contains the hands-on technical component of a master’s research project focused on evaluating the effectiveness and limitations of automated cloud security controls in AWS environments.

The project examines how Infrastructure as Code (Terraform) and Python-based automation can be used to detect common cloud misconfigurations, while also highlighting where automation alone is insufficient. The emphasis is on evidence-based analysis rather than assumptions about secure-by-default cloud configurations.

This repository represents the practical implementation that supports a graduate-level research paper.

---

## Project Objectives

- Deploy a reproducible AWS environment using Infrastructure as Code  
- Introduce controlled and intentional cloud security misconfigurations  
- Programmatically collect security-relevant configuration data  
- Analyze which risks are detected and which are missed by automation  
- Support research-driven conclusions about cloud security governance  

---

## Technologies Used

**Cloud Platform**
- Amazon Web Services (AWS)

**Infrastructure as Code**
- Terraform

**Scripting and Analysis**
- Python
- Boto3 (AWS SDK for Python)

**Security Focus Areas**
- Identity and Access Management (IAM) permissions  
- S3 public access configuration  
- Network exposure through security group rules  

---

## Infrastructure Summary

The Terraform configuration provisions a minimal AWS environment containing:

- An S3 bucket with public access protections disabled  
- A security group allowing overly permissive inbound access  
- An IAM role attached to an intentionally over-permissive policy  

All misconfigurations are intentional, isolated, and created solely for research and learning purposes.

---

## Methodology

1. Provision AWS infrastructure using Terraform  
2. Establish known misconfigurations  
3. Export Terraform outputs for analysis  
4. Collect AWS configuration data using Python and Boto3  
5. Analyze detected risks and automation blind spots  
6. Document findings for academic evaluation  

---

## Findings Summary

The Python audit script identifies:

- Publicly accessible S3 bucket configurations  
- Overly permissive security group rules  
- IAM roles with excessive permissions  

Results demonstrate that automation reliably detects common misconfigurations, while reinforcing that context and architectural intent still require human judgment.

---

## Scope and Limitations

- Not a production security tool  
- Limited to a small, controlled AWS environment  
- Focuses on detection rather than remediation  
- Single-account evaluation  

---

## Cleanup

To remove all deployed resources:

terraform destroy

---

## Academic Context

This repository supports a master’s research paper examining cloud misconfiguration risk, automation bias in security tooling, and the role of Infrastructure as Code in cloud security governance.

---

## Key Takeaway

Automation improves visibility and consistency, but it does not eliminate cloud security risk. Automated controls must be evaluated using evidence to understand both their strengths and their limitations.

