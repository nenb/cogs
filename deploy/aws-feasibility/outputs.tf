output "campaign" {
  description = "Non-secret identifiers required for bounded validation and cleanup."
  value = {
    region                    = var.aws_region
    batch_commitment          = var.batch_commitment
    cycle_ordinal             = var.cycle_ordinal
    availability_zone         = var.availability_zone
    instance_id               = aws_instance.host.id
    instance_type             = aws_instance.host.instance_type
    instance_state            = aws_instance.host.instance_state
    ami_id                    = data.aws_ami.ubuntu.id
    ami_owner_id              = var.ami_owner_id
    ami_commitment            = var.ami_commitment
    control_revision          = var.control_revision
    rootfs_descriptor_sha256  = var.rootfs_descriptor_sha256
    launch_template_id        = aws_launch_template.host.id
    launch_template_version   = aws_launch_template.host.latest_version
    root_volume_id            = aws_instance.host.root_block_device[0].volume_id
    primary_eni_id            = aws_instance.host.primary_network_interface_id
    nested_virtualization     = aws_launch_template.host.cpu_options[0].nested_virtualization
    ssm_managed_instance      = aws_instance.host.id
    expiry                    = var.expires_at
    termination_schedule_name = aws_scheduler_schedule.terminate.name
    purpose                   = local.purpose
    source_revision           = var.source_revision
  }
}
