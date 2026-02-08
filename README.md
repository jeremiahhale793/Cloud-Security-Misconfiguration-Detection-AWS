\# Evidence-Based Evaluation of Automated Cloud Security Controls



\## Overview

This repository contains the hands-on component of a master’s research project focused on evaluating the effectiveness and limitations of automated cloud security controls. The project examines how Infrastructure as Code and scripting-based automation can be used to identify cloud misconfigurations, while also highlighting where automation falls short.



The work prioritizes evidence-based analysis over assumptions about secure-by-default cloud environments.



---



\## Project Goals

\- Deploy a reproducible AWS cloud environment using Infrastructure as Code

\- Introduce controlled and intentional security misconfigurations

\- Programmatically collect security-relevant configuration data

\- Analyze findings to assess what automated checks detect and miss

\- Support research-driven conclusions about cloud security automation



---



\## Technologies Used

\- \*\*Cloud Provider:\*\* AWS  

\- \*\*Infrastructure as Code:\*\* Terraform  

\- \*\*Scripting \& Analysis:\*\* Python  



\*\*Security Focus Areas\*\*

\- IAM policy permissions

\- S3 public access configuration

\- Network exposure via security groups



---



\## Repository Structure

.

├── main.tf

├── variables.tf

├── terraform.tfvars

├── README.md



---



\## Infrastructure Summary

The Terraform configuration deploys a minimal AWS environment containing:



\- An S3 bucket with public access controls disabled

\- A security group with an overly permissive inbound rule

\- An IAM role attached to an intentionally over-permissive policy



These configurations are intentional and controlled and exist solely for evaluation and learning purposes.



---



\## Methodology

1\. Provision cloud infrastructure using Terraform

2\. Establish baseline configurations and known misconfigurations

3\. Collect configuration data programmatically

4\. Analyze results to identify detected risks and blind spots

5\. Document findings and limitations for research analysis



---



\## Scope and Limitations

\- This repository is not a production-ready security tool

\- The environment is limited to a single AWS account and a small set of services

\- Findings focus on detection capability, not automated remediation



---



\## Cleanup

terraform destroy



---



\## Academic Context

This project supports a master’s research paper examining cloud misconfiguration risk, automation bias, and the role of Infrastructure as Code in cloud security governance.



---



\## Key Takeaway

Automation improves consistency, but it does not eliminate cloud security risk. Automated controls must be evaluated with evidence to understand their effectiveness and limitations.

