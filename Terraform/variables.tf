variable "region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Prefix used to name resources"
  type        = string
  default     = "Jeremiah-Cloud-Audit"
}

variable "allowed_ip_for_ssh" {
  description = "Your public IP in CIDR form for safer SSH examples (optional). Example: 1.2.3.4/32"
  type        = string
  default     = "0.0.0.0/0"
}

variable "tags" {
  description = "Tags applied to all resources"
  type        = map(string)
  default = {
    Owner   = "Jeremiah"
    Project = "MastersProject"
  }
} 