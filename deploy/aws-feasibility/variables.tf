variable "aws_profile" {
  description = "Local shared-configuration profile; credentials are never inputs or state values."
  type        = string
  default     = "nebula"

  validation {
    condition     = var.aws_profile == "nebula"
    error_message = "The Stage 2 campaign is bound to the designated nebula profile."
  }
}

variable "aws_region" {
  description = "Single approved feasibility region."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = var.aws_region == "us-east-1"
    error_message = "The initial campaign is restricted to us-east-1."
  }
}

variable "availability_zone" {
  description = "Availability Zone selected after offering checks."
  type        = string
  default     = "us-east-1a"

  validation {
    condition     = contains(["us-east-1a", "us-east-1b", "us-east-1c", "us-east-1d", "us-east-1f"], var.availability_zone)
    error_message = "The zone must be one of the discovery-time c8i-flex.large offerings."
  }
}

variable "instance_type" {
  description = "One CPU-only nested-virtualization candidate."
  type        = string
  default     = "c8i-flex.large"

  validation {
    condition     = var.instance_type == "c8i-flex.large"
    error_message = "Only c8i-flex.large is approved; a fallback requires a new reviewed plan."
  }
}

variable "source_revision" {
  description = "Exact reviewed Git source revision attached to every resource."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{40}$", var.source_revision))
    error_message = "source_revision must be one lowercase 40-character Git revision."
  }
}

variable "expires_at" {
  description = "Explicit RFC3339 UTC expiry, normally four hours after apply."
  type        = string

  validation {
    condition     = can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.expires_at)) && endswith(var.expires_at, "Z")
    error_message = "expires_at must be an RFC3339 UTC timestamp ending in Z."
  }
}

variable "budget_alert_email" {
  description = "Owner email for campaign budget alerts; supplied out of band and retained only in local state/AWS Budgets."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", var.budget_alert_email))
    error_message = "budget_alert_email must be a valid email address."
  }
}

variable "account_id_sha256" {
  description = "Public binding for the designated AWS account without committing its account number."
  type        = string
  default     = "65eb8fbcacd1a51be6de86ac302df96a98a41c6190a4a161bf720592bf6a2bb7"

  validation {
    condition     = var.account_id_sha256 == "65eb8fbcacd1a51be6de86ac302df96a98a41c6190a4a161bf720592bf6a2bb7"
    error_message = "The campaign account binding cannot be overridden."
  }
}
