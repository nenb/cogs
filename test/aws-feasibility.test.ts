import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

const root = resolve(import.meta.dirname, "..");
const read = (path: string) => readFileSync(resolve(root, path), "utf8");

test("AWS fixture is pinned to one CPU-only nested-virtualization host", () => {
  const versions = read("deploy/aws-feasibility/versions.tf");
  const main = read("deploy/aws-feasibility/main.tf");
  const variables = read("deploy/aws-feasibility/variables.tf");
  assert.match(versions, /required_version = "= 1\.12\.4"/);
  assert.match(versions, /version = "= 6\.54\.0"/);
  assert.equal((main.match(/resource "aws_instance"/g) ?? []).length, 1);
  assert.match(variables, /var\.instance_type == "c8i-flex\.large"/);
  assert.match(main, /nested_virtualization = "enabled"/);
  assert.match(main, /core_count\s+= 1/);
  assert.match(main, /threads_per_core\s+= 2/);
  assert.doesNotMatch(main, /resource "aws_(?:eks|nat_gateway|eip|lb|efs|autoscaling|spot_fleet|sagemaker)/);
});

test("AWS fixture has no inbound rule and requires three independent termination controls", () => {
  const main = read("deploy/aws-feasibility/main.tf");
  assert.doesNotMatch(main, /\bingress\s*\{/);
  assert.match(main, /action_after_completion\s+= "DELETE"/);
  assert.match(main, /ec2:terminateInstances/);
  assert.match(main, /schedule-group\/default/);
  assert.doesNotMatch(main, /schedule\/default\/\$\{local\.name\}-terminate/);
  assert.match(main, /instance_initiated_shutdown_behavior = "terminate"/);
  assert.match(main, /shutdown -P \+220/);
  assert.match(main, /limit_amount = "20"/);
});

test("AWS runtime validation requires active KVM and a distinct root Kata guest", () => {
  const remote = read("deploy/aws-feasibility/remote/validate-runtime.sh");
  const controller = read("deploy/aws-feasibility/run-runtime-validation.sh");
  assert.match(remote, /qemu-system-x86_64 -S -nodefaults -display none -machine accel=kvm/);
  assert.match(remote, /query-kvm/);
  assert.match(remote, /'enabled': True, 'present': True/);
  assert.match(remote, /kata_version=3\.32\.0/);
  assert.match(remote, /kata-static-\$kata_version-amd64\.tar\.zst/);
  assert.match(remote, /1449ecea50bd91fa73a94648db195d18950fe869ba4b1f12d05f55f1fa7c1b01/);
  assert.match(remote, /guest_uid.*== 0/);
  assert.match(remote, /guest_kernel.*!=.*host_kernel/);
  assert.doesNotMatch(remote, /accel=tcg|--runtime.*runc/);
  assert.match(remote, /cogs-stage2-failure-stage=/);
  assert.match(controller, /runtime-failure\.json/);
  assert.match(controller, /runtime-command-id\.txt/);
  assert.match(controller, /timeout 2700/);
  assert.match(controller, /nested_virtualization.*enabled/);
});

test("AWS apply and cleanup scripts preserve manual and tag-bound gates", () => {
  const apply = read("deploy/aws-feasibility/apply.sh");
  const plan = read("deploy/aws-feasibility/plan.sh");
  const destroy = read("deploy/aws-feasibility/destroy.sh");
  const inventory = read("deploy/aws-feasibility/inventory.sh");
  const installer = read("scripts/install-opentofu.sh");
  assert.match(apply, /COGS_AWS_APPLY_APPROVED/);
  assert.match(apply, /apply-one-cpu-instance/);
  assert.match(apply, /destroy -auto-approve/);
  assert.match(plan, /-var-file=\.state\/campaign\.auto\.tfvars\.json/);
  assert.match(destroy, /-var-file=\.state\/campaign\.auto\.tfvars\.json/);
  assert.match(inventory, /stage-2-nested-virtualization/);
  assert.match(inventory, /total == 0/);
  assert.match(installer, /version=1\.12\.4/);
  assert.equal((installer.match(/sha256:/g) ?? []).length, 0, "installer stores raw expected digests only");
  assert.equal((installer.match(/expected=[0-9a-f]{64}/g) ?? []).length, 4);
});
