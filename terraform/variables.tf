variable "region" {
  description = "Single region for the whole lab. IAM events are only delivered in us-east-1."
  type        = string
  default     = "us-east-1"
}

variable "alert_email" {
  description = "Email address that receives SNS alerts. Set in terraform.tfvars (gitignored)."
  type        = string
}

variable "detection_enabled" {
  description = "false = rules DISABLED (the 'detection off' proof run). true = rules ENABLED."
  type        = bool
  default     = true
}

variable "remediate" {
  description = "false = Lambda alerts only and never changes anything."
  type        = bool
  default     = true
}

variable "lab_tag_key" {
  type    = string
  default = "lab"
}

variable "lab_tag_value" {
  type    = string
  default = "p5-threat-detection"
}

variable "stratus_prefix" {
  description = "Name prefix for resources Stratus Red Team creates. Confirm at warmup."
  type        = string
  default     = "stratus-red-team-"
}

variable "log_retention_days" {
  type    = number
  default = 14
}
