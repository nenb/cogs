output "campaign" {
  description = "Non-secret identifiers required for bounded validation and cleanup."
  value = {
    region                    = var.aws_region
    availability_zone         = var.availability_zone
    instance_id               = aws_instance.host.id
    instance_type             = aws_instance.host.instance_type
    instance_state            = aws_instance.host.instance_state
    ami_id                    = data.aws_ami.ubuntu.id
    launch_template_id        = aws_launch_template.host.id
    launch_template_version   = aws_launch_template.host.latest_version
    nested_virtualization     = aws_launch_template.host.cpu_options[0].nested_virtualization
    ssm_managed_instance      = aws_instance.host.id
    expiry                    = var.expires_at
    termination_schedule_name = aws_scheduler_schedule.terminate.name
    purpose                   = local.purpose
    source_revision           = var.source_revision
  }
}
