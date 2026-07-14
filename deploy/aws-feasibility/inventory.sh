#!/usr/bin/env bash
set -euo pipefail
: "${AWS_PROFILE:=nebula}"
export AWS_PROFILE AWS_REGION=us-east-1
purpose=stage-2-nested-virtualization
prefix=cogs-s2-
count() { [[ "$1" =~ ^[0-9]+$ ]] || { printf 'invalid inventory count\n' >&2; exit 1; }; printf '%s' "$1"; }

instances=$(count "$(aws ec2 describe-instances --filters "Name=tag:cogs:purpose,Values=$purpose" Name=instance-state-name,Values=pending,running,shutting-down,stopping,stopped --query 'length(Reservations[].Instances[])' --output text)")
volumes=$(count "$(aws ec2 describe-volumes --filters "Name=tag:cogs:purpose,Values=$purpose" --query 'length(Volumes[])' --output text)")
vpcs=$(count "$(aws ec2 describe-vpcs --filters "Name=tag:cogs:purpose,Values=$purpose" --query 'length(Vpcs[])' --output text)")
subnets=$(count "$(aws ec2 describe-subnets --filters "Name=tag:cogs:purpose,Values=$purpose" --query 'length(Subnets[])' --output text)")
gateways=$(count "$(aws ec2 describe-internet-gateways --filters "Name=tag:cogs:purpose,Values=$purpose" --query 'length(InternetGateways[])' --output text)")
route_tables=$(count "$(aws ec2 describe-route-tables --filters "Name=tag:cogs:purpose,Values=$purpose" --query 'length(RouteTables[])' --output text)")
groups=$(count "$(aws ec2 describe-security-groups --filters "Name=tag:cogs:purpose,Values=$purpose" --query 'length(SecurityGroups[])' --output text)")
launch_templates=$(count "$(aws ec2 describe-launch-templates --filters "Name=tag:cogs:purpose,Values=$purpose" --query 'length(LaunchTemplates[])' --output text)")
addresses=$(count "$(aws ec2 describe-addresses --filters "Name=tag:cogs:purpose,Values=$purpose" --query 'length(Addresses[])' --output text)")
roles=$(count "$(aws iam list-roles --query "length(Roles[?starts_with(RoleName, '$prefix')])" --output text)")
profiles=$(count "$(aws iam list-instance-profiles --query "length(InstanceProfiles[?starts_with(InstanceProfileName, '$prefix')])" --output text)")
schedules=$(count "$(aws scheduler list-schedules --query "length(Schedules[?starts_with(Name, '$prefix')])" --output text)")
budgets=$(count "$(aws budgets describe-budgets --account-id "$(aws sts get-caller-identity --query Account --output text)" --query "length(Budgets[?starts_with(BudgetName, '$prefix')])" --output text)")

total=$((instances + volumes + vpcs + subnets + gateways + route_tables + groups + launch_templates + addresses + roles + profiles + schedules + budgets))
printf '{"version":"cogs.aws-zero-inventory/v1alpha1","region":"us-east-1","purpose":"%s","counts":{"instances":%d,"volumes":%d,"vpcs":%d,"subnets":%d,"internet_gateways":%d,"route_tables":%d,"security_groups":%d,"launch_templates":%d,"elastic_ips":%d,"iam_roles":%d,"instance_profiles":%d,"schedules":%d,"budgets":%d},"total":%d}\n' \
  "$purpose" "$instances" "$volumes" "$vpcs" "$subnets" "$gateways" "$route_tables" "$groups" "$launch_templates" "$addresses" "$roles" "$profiles" "$schedules" "$budgets" "$total"
(( total == 0 )) || { printf 'campaign resources remain\n' >&2; exit 1; }
