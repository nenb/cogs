"""Immutable SSH-stable process policy plus separate ADR0099 runtime-owner policy."""
from types import MappingProxyType

POLICY_VERSION = "cogs.stage2-kata-command-policy/v4-process-only-ssh-stable-1"
CLEANUP_RESERVE_NS = 2_000_000_000
SSH_TOTAL_NS = 1_200_000_000_000
SSH_CLEANUP_RESERVE_NS = 30_000_000_000
HOST_TOOL_CONTRACT_VERSION = "cogs.stage2-kata-tool-closure/v1"
KEY_STAGE_PREFIX = "/var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/.state/completion-v1/kata-key-stage-v1-"
KEY_STAGE = KEY_STAGE_PREFIX + "{operation_token}"
KEY_COMMANDS = MappingProxyType({
    "SSH_KEYGEN_CLIENT": ("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                          "-C", "cogs-stage2-client-v1", "-f", KEY_STAGE + "/client"),
    "SSH_PUBLIC_CLIENT": ("/usr/bin/ssh-keygen", "-y", "-f", KEY_STAGE + "/client"),
    "SSH_KEYGEN_SERVER": ("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                          "-C", "cogs-stage2-server-v1", "-f", KEY_STAGE + "/server"),
    "SSH_PUBLIC_SERVER": ("/usr/bin/ssh-keygen", "-y", "-f", KEY_STAGE + "/server"),
})
KEY_COMMAND_ORDER = tuple(KEY_COMMANDS)
SSH_COMMANDS = ("SSH_READY", "SSH_READINESS")
ATTESTED_COMMANDS = frozenset({*SSH_COMMANDS, *KEY_COMMANDS})
# Exact final contract descriptors are inserted only by a later reviewed host
# contract commit. The real issuer consumes this object by identity and cannot
# issue while it is empty.
REVIEWED_HOST_TOOL_CONTRACTS = MappingProxyType({})
REVIEWED_SYNTHETIC_HOST_TOOL_CONTRACTS = MappingProxyType({
    "ssh": MappingProxyType({"contract_path": "/tmp/cogs-stage2-attested-ssh-contract-v1.json",
                              "contract_sha256": "33bb651509a266f2e5f9c40f259cf18b3699d8a66da99725903f5bfae2a0b527"}),
    "ssh-keygen": MappingProxyType({"contract_path": "/tmp/cogs-stage2-attested-ssh-keygen-contract-v1.json",
                                     "contract_sha256": "82c40b2972fe0ea40b860fcf4aaee0b5b885ceba93aa0a6ac2f58f9ba91c501c"}),
})
# Additive current-codec test route. The historical synthetic mapping above is
# retained byte-for-byte for the V1 process/recovery matrices.
REVIEWED_SYNTHETIC_HOST_TOOL_CONTRACTS_V3 = MappingProxyType({
    "ssh": MappingProxyType({"contract_path": "/tmp/cogs-stage2-attested-ssh-contract-v3.json",
                              "contract_sha256": "d740640973f8aa8f152207970e3cdd6a7d0b6864eca4e5b274ce903cf3f4527a"}),
    "ssh-keygen": MappingProxyType({"contract_path": "/tmp/cogs-stage2-attested-ssh-keygen-contract-v3.json",
                                     "contract_sha256": "272ab6f074b96d515402396e1768b1a04a43ace1fc706c044e457f19d1029814"}),
})
_ATTESTED_EXECUTABLES = {}
ATTESTED_EXECUTABLES = MappingProxyType(_ATTESTED_EXECUTABLES)
def _policy_inserter_route():
    available = [True]
    def install(command_ids, value, reviewed):
        if (not (reviewed is REVIEWED_HOST_TOOL_CONTRACTS
                 or reviewed is REVIEWED_SYNTHETIC_HOST_TOOL_CONTRACTS
                 or reviewed is REVIEWED_SYNTHETIC_HOST_TOOL_CONTRACTS_V3)
                or type(command_ids) is not tuple
                or not command_ids or not set(command_ids) <= ATTESTED_COMMANDS
                or type(value) is not dict or set(value) != {
                    "executable_sha256", "tool_closure_sha256", "executable_path",
                    "contract_version"}):
            raise RuntimeError("unreviewed executable policy insertion")
        if any(name in _ATTESTED_EXECUTABLES for name in command_ids):
            raise RuntimeError("executable policy already inserted")
        frozen = MappingProxyType(dict(value))
        for name in command_ids: _ATTESTED_EXECUTABLES[name] = frozen
    def take():
        if not available[0]: raise RuntimeError("policy inserter already issued")
        available[0] = False
        return install
    return take
_take_attested_policy_inserter = _policy_inserter_route()
del _policy_inserter_route


def _v2_policy_inserter_route():
    available = [True]
    def install(command_ids, value):
        if (type(command_ids) is not tuple or not command_ids
                or not set(command_ids) <= ATTESTED_COMMANDS
                or type(value) is not dict or set(value) != {
                    "executable_sha256", "tool_closure_sha256", "executable_path",
                    "contract_version"}):
            raise RuntimeError("invalid V2 executable policy insertion")
        if any(name in _ATTESTED_EXECUTABLES for name in command_ids):
            raise RuntimeError("executable policy already inserted")
        frozen = MappingProxyType(dict(value))
        for name in command_ids:
            _ATTESTED_EXECUTABLES[name] = frozen
    def take():
        if not available[0]:
            raise RuntimeError("V2 policy inserter already issued")
        available[0] = False
        return install
    return take


_take_v2_attested_policy_inserter = _v2_policy_inserter_route()
del _v2_policy_inserter_route
DEFERRED_COMMANDS = frozenset({"CTR_RUN"})

# Byte-compatible protected v1 vocabulary; B1 IDs are journal-derived and do
# not enter the fixed process digest table.
LEGACY_V1_VERSION = "cogs.stage2-kata-command-v1/protected-746"
LEGACY_COMMANDS = frozenset({
    "IP_NETNS_ADD", "IP_LINK_ADD", "IP_LINK_MOVE", "IP_HOST_ADDRESS_ADD",
    "IP_HOST_LINK_UP", "IP_PEER_RENAME", "IP_PEER_ADDRGEN_NONE", "IP_LOOPBACK_UP",
    "IP_GUEST_ADDRESS_ADD", "IP_GUEST_LINK_UP", "IP_NETNS_REMOVE", "IP_HOST_LINKS",
    "IP_HOST_ADDRESSES", "IP_HOST_ROUTES4", "IP_HOST_ROUTES6", "IP_NS_LINKS",
    "IP_NS_ADDRESSES", "IP_NS_ROUTES4", "IP_NS_ROUTES6", "TC_QDISC",
    "TC_INGRESS_FILTER", "NFT_INSTALL", "NFT_REMOVE", "NFT_TABLE",
    "SSH_KEYGEN_CLIENT", "SSH_KEYGEN_SERVER", "SSH_PUBLIC_CLIENT", "SSH_PUBLIC_SERVER",
    "CTR_RUN", "CTR_CONTAINER_INFO", "CTR_CONTAINER_LIST", "CTR_TASK_LIST",
    "CTR_TASK_TERM", "CTR_TASK_KILL", "CTR_TASK_REMOVE", "CTR_CONTAINER_REMOVE", "SSH_READY",
})
B1_COMMAND_IDS = frozenset({"IP_HOST_ADDRGEN_NONE", "IP_HOST_LINK_REMOVE", "IP_NETNS_LIST",
    "IP_ALL_LINKS", "IP_ALL_ADDRESSES", "IP_ALL_ROUTES4", "IP_ALL_ROUTES6", "NFT_RULESET",
    "IP_VETH_ADD_ATOMIC", "NFT_INSTALL_OWNED", "NFT_REMOVE_ATOMIC", "TC_QDISC",
    "TC_INGRESS_FILTER"})

_IDENTITY_CREATE_DIGESTS = (
    "57da97bf9cad7e6f4b8bdc2e283be28cd7bf4860ea6b41dfe60112214f511a72",
    "2e2f373d5154ddbfbeea4ae24799ddbbc321f272a0a44474ef4fa9feda7706cf",
)
_POLICY_SHA256 = {
    "CTR_CONTAINER_INFO": "2815a5d4b7e306c3eee1030f3328bef1a4b7dab914cadc79aea4b215bd0977aa",
    "CTR_CONTAINER_LIST": "ba75e006cbdf34f5e6fdd2006b14bf9273a8e3ce7d6951bc30cd2aa9d54be2a9",
    "CTR_CONTAINER_REMOVE": "6707260cbfdd20df52e020160490f4e0ed28be1f8e3f46f0183c54e4b54b854e",
    "CTR_TASK_KILL": "0265c47f6f0edab4caf082451b926f7d07da4b1fda52f8e81bd6771fcc4139e6",
    "CTR_TASK_LIST": "2208b3c2544259064211be7c0ca934e7f817a4cdb13eb25fd076baf260c67447",
    "CTR_TASK_REMOVE": "7d38e7ee2c13f5d6c19bf7b2c1dd44244c3100de1ea621c92724900542625548",
    "CTR_TASK_TERM": "a834973f3c29b2ecafe99919da4c461c3e08042946991675d7890cef29567ef0",
    "IP_GUEST_ADDRESS_ADD": "83428606b3855e2b2f9178968cd9ed6a374ee6cc4be7f69c75bb5a6aaf737ee9",
    "IP_GUEST_LINK_UP": "83e3422198161d4d836cd1042da2afe63104c1456e2d515ebe39dd0296e6b3cf",
    "IP_HOST_ADDRESSES": "50e8f664c42b257c40b25926325d5807c1b26cbe82fcc8d32b5d07de08516ae0",
    "IP_HOST_ADDRESS_ADD": "d4f2e42e27549407f3407811f788c4572b0b4801c71875867f0dcf95d948443e",
    "IP_HOST_LINKS": "24d960ab30ea659561f5e3b44eea44881b5f1ea6eb7a113d306cc38d2143b7e0",
    "IP_HOST_LINK_UP": "87eed7c4f1cf1208a243f9acf4113307311d76488776855737c25e625448c676",
    "IP_HOST_ROUTES4": "def44eaafdc8873044f00932e84bd20b51c5688fe988a969aa166f0a1e173177",
    "IP_HOST_ROUTES6": "0dc7e8f9f2e6ca67725d01711bf0e774d3573aa8ad059dd82c4f2a660bdfc5d7",
    "IP_LINK_ADD": "fa96d5c361007f8eb89c0ebf5ccba9eab93ea71a180253450e34bb50620324ed",
    "IP_LINK_MOVE": "1beba4a83d823ae9410c34c684adaaeec86a37dce24f13ae949383df23e7ece4",
    "IP_LOOPBACK_UP": "afc6f04177744abcb05424b7685f397a0bd7a00484aad50c9d9e880abc8eb2cf",
    "IP_NETNS_ADD": "28e72e3b635cf30be4571662cac19ec0eb4ca284ee0b25828e83c089d42c3d73",
    "IP_NETNS_REMOVE": "96f3c19b6fc79a2d068603db28929292d08c67aad9ea6a974b98073b46d59d1b",
    "IP_NS_ADDRESSES": "a72ec608e94b05a01c791d1633b02ad555e561a7b46d81cc4d17c09fb18c5fd1",
    "IP_NS_LINKS": "20b9fefc889de5d9c9ea10c2f7635bfc80af5230dd0acebb8423e14f8c53855d",
    "IP_NS_ROUTES4": "4293fbb68a4f000cc2544817d532151f747145c6921e9c893641b861cc13b96d",
    "IP_NS_ROUTES6": "7721fd08e65d890cc7b5730a017c5b1f953a076a5e150f995fe139e8e6033bc4",
    "IP_PEER_ADDRGEN_NONE": "1e472a86001cb41fc793126c915e856c3ca1ead588b6ad7b4889a9a67a1a6d30",
    "IP_PEER_RENAME": "b96a2714c3b3fe1c1a686c9790b321d2cc6003edcce15340bf8f3fcb389bb0d4",
    "NFT_INSTALL": "64bc4796579f9f7676baa58f927a4608e2a28b0dfccd569d93922458256226bc",
    "NFT_REMOVE": "e05578f9ddf2bd48b9e8dd4fab15450121204cb312224c47337bd54992a46afa",
    "NFT_TABLE": "c81d934f138b8c4e89faff3d51620eab944a100e92e077242c9ce02e37f93b0d",
    "SSH_READY": "fc798706a66c9a9676311bf2f43483c147b672aebb4c89869618975c29de7497",
    "SSH_READINESS": "a7fff074ab3d551e9140ac3e3b261f3f937224261c1b12b4da5860d2734ee9ef",
    "SSH_KEYGEN_CLIENT": _IDENTITY_CREATE_DIGESTS[0],
    "SSH_PUBLIC_CLIENT": "1f68af8c1dde18e50dc62e3c2a6f5d2bf2d9518056df9955577f35a0ca2e2526",
    "SSH_KEYGEN_SERVER": _IDENTITY_CREATE_DIGESTS[1],
    "SSH_PUBLIC_SERVER": "3e98ed1b3384265e32bd52a8b343ed83d2c16e6f91230fa2d8836e418f35607c",
    "CONTAINERD_START": "d4bffc7bfe628d4cdf3440bc4156db5891cd3941e791dac92a17bc7922bbb8c2",
}
POLICY_SHA256 = MappingProxyType(_POLICY_SHA256)
del _IDENTITY_CREATE_DIGESTS, _POLICY_SHA256

_OCCURRENCES = {name: ("BASELINES_CAPTURED",) for name in POLICY_SHA256}
for _name in KEY_COMMANDS: _OCCURRENCES[_name] = ("ROOTFS_LEASED",)
for _name in SSH_COMMANDS: _OCCURRENCES[_name] = ("RUNTIME_READY",)
OCCURRENCES = MappingProxyType(_OCCURRENCES)
PHASES = MappingProxyType(dict(_OCCURRENCES))
MAX_OCCURRENCES = MappingProxyType({name: 1 for name in _OCCURRENCES})
del _name, _OCCURRENCES

RUNTIME_POLICY_VERSION = "cogs.stage2-kata-runtime-policy/v9-coherent-teardown-independent-qmp-1"; RUNTIME_POLICY_SHA256 = "45870a704fcdebf2b212fb722f6e68d23b3efa19461f9cc4699f70af931e4992"
RUNTIME_POST_KILL_OBSERVATIONS = 8; RUNTIME_POST_KILL_INTERVAL_NS = 250_000_000
RUNTIME_RETIREMENT_OBSERVATIONS = 16; RUNTIME_RETIREMENT_INTERVAL_NS = 250_000_000
BASE = "/var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/.state/completion-v1"; RUNTIME_ALIAS = "/run/c42d"; CONTAINERD_ADDRESS = RUNTIME_ALIAS + "/s"; CONTAINERD_ROOT = RUNTIME_ALIAS + "/r"; CONTAINERD_STATE = RUNTIME_ALIAS + "/t"
STAGED_CONTAINERD = BASE + "/kata-runtime-v1/bin/containerd"; STAGED_CTR = BASE + "/kata-runtime-v1/bin/ctr"
RUNTIME_CONFIG = BASE + "/kata-runtime-v1/configuration-qemu-observer.toml"
CONTAINERD_ARCHIVE_SHA256 = "af3e82bac6abed58d45956c653244aa2be583359a9753614278ef652012f2883"; CONTAINERD_ARCHIVE_SIZE = 33_645_699
CONTAINERD_EXTRACTION = (("bin/containerd", 44_050_184, "f5d70cf9a249a70a70c379ba8f7259ea91122650cc06103bc0fc44a04dbc54da", 0o500),
    ("bin/ctr", 22_143_160, "448b1d7a2da84b6265dc4685afcc6c69a6299de43b942b8a3d6d540f6585d1db", 0o500))
CONTAINERD_EXTRACTION_SHA256 = "ffd892ec4ef2da92a824d78645b75e66972bbe44d664062026d324a58ab88512"
INPUT_SHARE = BASE + "/kata-input-v1/share"; NETNS_PATH = "/run/netns/cogs-stage2-ssh"; NAMESPACE = "cogs-stage2-completion-v1"
BOOTSTRAP = """set -eu
umask 077
/bin/mkdir -p /run/sshd /run/cogs-stage2-ssh/work
/bin/chown 0:0 /run/sshd /run/cogs-stage2-ssh/work
/bin/chmod 0755 /run/sshd
/bin/chmod 0700 /run/cogs-stage2-ssh/work
[ \"$(/usr/bin/stat -c '%u:%g:%a:%F' -- /run/sshd)\" = \"0:0:755:directory\" ]
[ \"$(/usr/bin/stat -c '%u:%g:%a:%F' -- /run/cogs-stage2-ssh/work)\" = \"0:0:700:directory\" ]
[ ! -e /run/cogs-stage2-ssh/sshd.pid ]
exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
"""
CTR_MOUNTS = ("type=tmpfs,src=tmpfs,dst=/run/cogs-stage2-ssh,options=rw:nosuid:nodev:noexec:mode=0700:size=67108864:nr_inodes=16384",
    f"type=bind,src={INPUT_SHARE}/ssh_host_ed25519_key,dst=/run/cogs-stage2-ssh/ssh_host_ed25519_key,options=bind:ro:nosuid:nodev:noexec:private",
    f"type=bind,src={INPUT_SHARE}/authorized_keys,dst=/run/cogs-stage2-ssh/authorized_keys,options=bind:ro:nosuid:nodev:noexec:private",
    f"type=bind,src={INPUT_SHARE}/fixture,dst=/run/cogs-stage2-ssh/input,options=bind:ro:nosuid:nodev:noexec:private")
CTR_TAILS = MappingProxyType({"CTR_CONTAINER_INFO": ("containers", "info", "cogs-stage2-ssh-v1"),
    "CTR_CONTAINER_LIST": ("containers", "list"), "CTR_TASK_LIST": ("tasks", "list"),
    "CTR_TASK_TERM": ("tasks", "kill", "--signal", "SIGTERM", "cogs-stage2-ssh-v1"), "CTR_TASK_KILL": ("tasks", "kill", "--signal", "SIGKILL", "cogs-stage2-ssh-v1"),
    "CTR_TASK_REMOVE": ("tasks", "rm", "cogs-stage2-ssh-v1"), "CTR_CONTAINER_REMOVE": ("containers", "rm", "cogs-stage2-ssh-v1")})
RUNTIME_EXTENSION_COMMANDS = frozenset({"CONTAINERD_START", "CTR_RUN", *CTR_TAILS})
def ctr_run_argv(rootfs_token):
    if type(rootfs_token) is not str or len(rootfs_token) != 64 or any(c not in "0123456789abcdef" for c in rootfs_token): raise ValueError("rootfs token")
    mounts = tuple(value for row in CTR_MOUNTS for value in ("--mount", row)); root = BASE + "/rootfs-v1/operation-" + rootfs_token + "/rootfs"
    return (STAGED_CTR, "--address", CONTAINERD_ADDRESS, "--namespace", NAMESPACE, "run", "--runtime", "io.containerd.kata.v2",
        "--runtime-config-path", RUNTIME_CONFIG, "--rootfs", "--read-only",
        "--detach", "--with-ns", "network:/proc/{ctr-child-pid}/fd/202", *mounts, root,
        "cogs-stage2-ssh-v1", "/bin/sh", "-c", BOOTSTRAP)
def validate_runtime_policy(intent, genesis):
    command = intent.get("command_id")
    if command == "CTR_RUN": argv, deadline, duration, grammar = list(ctr_run_argv(genesis["rootfs_token"])), "runtime-start", 60_000_000_000, "text"
    elif command == "CONTAINERD_START":
        argv = [STAGED_CONTAINERD, "--address", CONTAINERD_ADDRESS, "--root", CONTAINERD_ROOT,
                "--state", CONTAINERD_STATE, "--config", BASE + "/kata-runtime-v1/containerd.toml"]
        deadline, duration, grammar = "runtime-start", 60_000_000_000, "empty"
    elif command in CTR_TAILS:
        argv = [STAGED_CTR, "--address", CONTAINERD_ADDRESS, "--namespace", NAMESPACE, *CTR_TAILS[command]]
        deadline = "observer" if command in {"CTR_CONTAINER_INFO", "CTR_CONTAINER_LIST", "CTR_TASK_LIST"} else "task-term" if command == "CTR_TASK_TERM" else "task-kill" if command == "CTR_TASK_KILL" else "remove"
        duration = {"observer": 5, "task-term": 15, "task-kill": 10, "remove": 20}[deadline] * 1_000_000_000; grammar = "text"
    else: return False
    expected = {"executable_role": "containerd" if command == "CONTAINERD_START" else "ctr", "executable_path": argv[0], "argv": argv,
        "stdin_hex": "", "policy_version": RUNTIME_POLICY_VERSION, "deadline_class": deadline, "duration_ns": duration,
        "cleanup_reserve_ns": min(CLEANUP_RESERVE_NS, duration // 2), "output_grammar": grammar, "stdout_limit": 65536, "stderr_limit": 65536, "inherited_fds": []}
    return all(intent.get(name) == value for name, value in expected.items())
_RUNTIME_TRACES = {"NETWORK_READY": ("CONTAINERD_START", "CTR_CONTAINER_LIST", "CTR_RUN"),
    "RUNTIME_READY": ("CTR_CONTAINER_INFO", "CTR_CONTAINER_LIST", "CTR_TASK_LIST"), "READINESS_REVOKED": ("CTR_TASK_LIST", "CTR_CONTAINER_INFO", "CTR_CONTAINER_LIST"),
    "OWNERSHIP_OBSERVED:task-exact": ("CTR_TASK_LIST", "CTR_TASK_TERM", "CTR_TASK_LIST", "CTR_TASK_KILL") + ("CTR_TASK_LIST",) * RUNTIME_POST_KILL_OBSERVATIONS,
    "TASK_STOPPED": ("CTR_TASK_REMOVE", "CTR_TASK_LIST"),
    "NETWORK_ABSENT": ("CTR_CONTAINER_REMOVE", "CTR_CONTAINER_LIST"),}
RUNTIME_TRACES = MappingProxyType(_RUNTIME_TRACES); _OWNED = _RUNTIME_TRACES["OWNERSHIP_OBSERVED:task-exact"]; RUNTIME_OWNERSHIP_TRACES = (_OWNED[:3],) + tuple(_OWNED[:5 + index] for index in range(RUNTIME_POST_KILL_OBSERVATIONS))
RUNTIME_PROVEN_ABSENT_TRACES = MappingProxyType({"TASK_STOPPED": ("CTR_TASK_LIST",), "NETWORK_ABSENT": ("CTR_CONTAINER_LIST",)})
_RUNTIME_OCCURRENCES = {name: tuple(phase.split(":", 1)[0] for phase, trace in _RUNTIME_TRACES.items() for item in trace if item == name) for name in RUNTIME_EXTENSION_COMMANDS}
RUNTIME_OCCURRENCES = MappingProxyType(_RUNTIME_OCCURRENCES); RUNTIME_PHASES = MappingProxyType({name: tuple(dict.fromkeys(phases)) for name, phases in _RUNTIME_OCCURRENCES.items()})
RUNTIME_MAX_OCCURRENCES = MappingProxyType({name: len(phases) for name, phases in _RUNTIME_OCCURRENCES.items()}); del _RUNTIME_TRACES, _RUNTIME_OCCURRENCES, _OWNED
