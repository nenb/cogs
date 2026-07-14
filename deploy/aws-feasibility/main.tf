data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

data "aws_ssm_parameter" "ubuntu_ami" {
  name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"
}

data "aws_ami" "ubuntu" {
  owners = ["099720109477"]

  filter {
    name   = "image-id"
    values = [nonsensitive(data.aws_ssm_parameter.ubuntu_ami.value)]
  }

  filter {
    name   = "state"
    values = ["available"]
  }
}

locals {
  name          = "cogs-s2-${substr(var.source_revision, 0, 8)}"
  purpose       = "stage-2-nested-virtualization"
  resolver_cidr = "10.77.0.2/32"
  tags = {
    "cogs:owner"           = "nenb"
    "cogs:purpose"         = local.purpose
    "cogs:source-revision" = var.source_revision
    "cogs:expires-at"      = var.expires_at
    "cogs:managed-by"      = "opentofu"
  }
}

check "designated_account" {
  assert {
    condition     = sha256(data.aws_caller_identity.current.account_id) == var.account_id_sha256
    error_message = "The active AWS profile does not identify the designated feasibility account."
  }
}

check "bounded_expiry" {
  assert {
    condition = (
      timecmp(var.expires_at, timeadd(timestamp(), "30m")) > 0 &&
      timecmp(var.expires_at, timeadd(timestamp(), "5h")) < 0
    )
    error_message = "Expiry must be more than 30 minutes and less than five hours from plan/apply."
  }
}

check "approved_ami" {
  assert {
    condition = (
      data.aws_ami.ubuntu.architecture == "x86_64" &&
      data.aws_ami.ubuntu.virtualization_type == "hvm" &&
      data.aws_ami.ubuntu.root_device_type == "ebs"
    )
    error_message = "The resolved Canonical AMI must be available x86_64 HVM with an EBS root."
  }
}

resource "aws_vpc" "campaign" {
  cidr_block           = "10.77.0.0/24"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = local.name }
}

resource "aws_internet_gateway" "campaign" {
  vpc_id = aws_vpc.campaign.id
  tags   = { Name = local.name }
}

resource "aws_subnet" "campaign" {
  vpc_id                  = aws_vpc.campaign.id
  cidr_block              = "10.77.0.0/26"
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = false

  tags = { Name = local.name }
}

resource "aws_route_table" "campaign" {
  vpc_id = aws_vpc.campaign.id
  tags   = { Name = local.name }
}

resource "aws_route" "internet" {
  route_table_id         = aws_route_table.campaign.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.campaign.id
}

resource "aws_route_table_association" "campaign" {
  subnet_id      = aws_subnet.campaign.id
  route_table_id = aws_route_table.campaign.id
}

resource "aws_security_group" "host" {
  name_prefix = "${local.name}-"
  description = "No inbound access; bounded outbound SSM and package setup"
  vpc_id      = aws_vpc.campaign.id

  egress {
    description = "HTTPS for SSM and signed package repositories"
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTP for package repository redirects during disposable setup"
    protocol    = "tcp"
    from_port   = 80
    to_port     = 80
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "UDP DNS only to the VPC resolver"
    protocol    = "udp"
    from_port   = 53
    to_port     = 53
    cidr_blocks = [local.resolver_cidr]
  }

  egress {
    description = "TCP DNS only to the VPC resolver"
    protocol    = "tcp"
    from_port   = 53
    to_port     = 53
    cidr_blocks = [local.resolver_cidr]
  }

  tags = { Name = local.name }
}

resource "aws_iam_role" "host" {
  name = "${local.name}-host"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
  tags = { Name = local.name }
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.host.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "host" {
  name = "${local.name}-host"
  role = aws_iam_role.host.name
  tags = { Name = local.name }
}

resource "aws_launch_template" "host" {
  name                   = local.name
  description            = "Disposable Cogs Stage 2 nested-KVM feasibility host"
  image_id               = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  ebs_optimized          = true
  update_default_version = true

  cpu_options {
    core_count            = 1
    threads_per_core      = 2
    nested_virtualization = "enabled"
  }

  block_device_mappings {
    device_name = data.aws_ami.ubuntu.root_device_name
    ebs {
      delete_on_termination = true
      encrypted             = true
      volume_size           = 30
      volume_type           = "gp3"
    }
  }

  iam_instance_profile {
    arn = aws_iam_instance_profile.host.arn
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_protocol_ipv6          = "disabled"
    http_put_response_hop_limit = 1
    http_tokens                 = "required"
    instance_metadata_tags      = "enabled"
  }

  network_interfaces {
    associate_public_ip_address = true
    delete_on_termination       = true
    device_index                = 0
    security_groups             = [aws_security_group.host.id]
    subnet_id                   = aws_subnet.campaign.id
  }

  tag_specifications {
    resource_type = "instance"
    tags          = merge(local.tags, { Name = local.name })
  }

  tag_specifications {
    resource_type = "volume"
    tags          = merge(local.tags, { Name = local.name })
  }

  user_data = base64encode("#!/usr/bin/env bash\nset -eu\nlogger -t cogs-stage-2 'arming guest-local termination fallback'\nshutdown -P +220\n")

  tags = { Name = local.name }
}

resource "aws_instance" "host" {
  launch_template {
    id      = aws_launch_template.host.id
    version = aws_launch_template.host.latest_version
  }

  instance_initiated_shutdown_behavior = "terminate"
  tags                                 = { Name = local.name }

  lifecycle {
    precondition {
      condition     = var.instance_type == "c8i-flex.large"
      error_message = "Only one CPU-only c8i-flex.large instance is approved."
    }
  }

  depends_on = [aws_iam_role_policy_attachment.ssm, aws_route.internet]
}

resource "aws_iam_role" "terminator" {
  name = "${local.name}-terminator"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "scheduler.amazonaws.com"
      }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:scheduler:${var.aws_region}:${data.aws_caller_identity.current.account_id}:schedule/default/${local.name}-terminate"
        }
      }
    }]
  })
  tags = { Name = local.name }
}

resource "aws_iam_role_policy" "terminator" {
  name = "terminate-exact-tagged-instance"
  role = aws_iam_role.terminator.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "ec2:TerminateInstances"
      Resource = aws_instance.host.arn
      Condition = {
        StringEquals = {
          "ec2:ResourceTag/cogs:purpose"         = local.purpose
          "ec2:ResourceTag/cogs:source-revision" = var.source_revision
          "ec2:ResourceTag/cogs:expires-at"      = var.expires_at
        }
      }
    }]
  })
}

resource "aws_scheduler_schedule" "terminate" {
  name                         = "${local.name}-terminate"
  description                  = "Independent four-hour Cogs feasibility instance termination"
  schedule_expression          = "at(${formatdate("YYYY-MM-DD'T'hh:mm:ss", var.expires_at)})"
  schedule_expression_timezone = "UTC"
  action_after_completion      = "DELETE"

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = "arn:${data.aws_partition.current.partition}:scheduler:::aws-sdk:ec2:terminateInstances"
    role_arn = aws_iam_role.terminator.arn
    input    = jsonencode({ InstanceIds = [aws_instance.host.id] })

    retry_policy {
      maximum_event_age_in_seconds = 300
      maximum_retry_attempts       = 3
    }
  }

  depends_on = [aws_iam_role_policy.terminator]
}

resource "aws_budgets_budget" "campaign" {
  name         = "${local.name}-20-usd"
  budget_type  = "COST"
  limit_amount = "20"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name   = "Service"
    values = ["Amazon Elastic Compute Cloud - Compute"]
  }

  dynamic "notification" {
    for_each = toset([25, 50, 100])
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value
      threshold_type             = "PERCENTAGE"
      notification_type          = "ACTUAL"
      subscriber_email_addresses = [var.budget_alert_email]
    }
  }

  tags = { Name = local.name }
}
