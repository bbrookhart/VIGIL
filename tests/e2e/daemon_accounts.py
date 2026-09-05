#!/usr/bin/env python3
"""Linux root-run test using four real kernel UIDs, no persistent user accounts.

Run only on a disposable test host: sudo python3 tests/e2e/daemon_accounts.py
target/debug/vigild. Fails (does not skip) without the required privileges.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

SERVICE, AGENT, OPERATOR, OUTSIDER = 61001, 61002, 61003, 61004


def run_as(uid, argv, **kwargs):
    return subprocess.run(argv, user=uid, group=uid, extra_groups=[],
                          capture_output=True, text=True, timeout=10, **kwargs)


def main():
    assert os.geteuid() == 0, "cross-account test requires root on a disposable host"
    source = Path(sys.argv[1]).resolve()
    root = Path(tempfile.mkdtemp(prefix="vigil-accounts-", dir="/var/lib"))
    root.chmod(0o755)
    process = None
    log = None
    try:
        binary = root / "vigild"
        shutil.copy2(source, binary)
        binary.chmod(0o755)
        state, runtime, workspace = [root / name for name in ("state", "run", "workspace")]
        for path, owner, mode in [(state, SERVICE, 0o700), (runtime, SERVICE, 0o755),
                                  (workspace, AGENT, 0o755)]:
            path.mkdir(); os.chown(path, owner, owner); path.chmod(mode)
        (workspace / "example.txt").write_text("must never be deleted by this service\n")
        socket = runtime / "authority.sock"
        command = [str(binary), "serve", "--state-dir", str(state), "--socket", str(socket),
                   "--agent-uid", str(AGENT), "--operator-uid", str(OPERATOR),
                   "--workspace", str(workspace), "--profile", "untrusted-agent"]

        def start():
            nonlocal process, log
            log = open(root / "daemon.log", "a")
            process = subprocess.Popen(command, user=SERVICE, group=SERVICE, extra_groups=[],
                                       stdout=log, stderr=log)
            for _ in range(100):
                if process.poll() is not None:
                    raise AssertionError((root / "daemon.log").read_text())
                if socket.exists():
                    return
                time.sleep(0.05)
            raise AssertionError("daemon did not bind")

        def stop():
            nonlocal process, log
            process.terminate(); process.wait(timeout=10); process = None
            log.close(); log = None

        def call(uid, request, ok=True, server_uid=SERVICE, endpoint=socket):
            result = run_as(uid, [str(binary), "call", "--socket", str(endpoint),
                                 "--server-uid", str(server_uid), "--request", json.dumps(request)])
            assert (result.returncode == 0) == ok, (request, result.stdout, result.stderr)
            return json.loads(result.stdout)["result"] if ok else result

        start()
        status = call(AGENT, {"method": "status"})
        assert status["execution_supported"] is False
        call(OUTSIDER, {"method": "status"}, ok=False)
        call(AGENT, {"method": "status"}, server_uid=OPERATOR, ok=False)
        for method in ("approvals", "checkpoint"):
            call(AGENT, {"method": method}, ok=False)

        request = {"method": "authorize", "action": "fs.delete", "resource": "example.txt"}
        decision = call(AGENT, request)
        assert decision["decision"]["outcome"] == "REQUIRE_APPROVAL", decision
        approvals = call(OPERATOR, {"method": "approvals"})
        assert len(approvals) == 1, approvals
        approval_id = approvals[0]["approval_id"]
        grant = {"method": "grant", "approval_id": approval_id, "max_uses": 1, "ttl_seconds": 60}
        call(AGENT, grant, ok=False)
        call(AGENT, {"method": "deny", "approval_id": approval_id}, ok=False)
        lease = call(OPERATOR, grant)
        assert lease["max_uses"] == 1, lease
        assert call(AGENT, request)["decision"]["outcome"] == "ALLOW"
        assert call(AGENT, request)["decision"]["outcome"] == "REQUIRE_APPROVAL"
        assert (workspace / "example.txt").exists(), "authority service executed a tool"
        checkpoint = call(OPERATOR, {"method": "checkpoint"})
        assert checkpoint["signature"]

        # Bypass the typed CLI to test forged fields at the server boundary.
        raw = """import socket,struct,sys,json
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
b=json.dumps({'method':'grant','approval_id':sys.argv[2],'max_uses':1,
              'ttl_seconds':60,'uid':61003}).encode()
s.sendall(struct.pack('!I',len(b))+b)
n=struct.unpack('!I',s.recv(4))[0]; data=b''
while len(data)<n: data+=s.recv(n-len(data))
assert json.loads(data)['ok'] is False
"""
        assert run_as(AGENT, [sys.executable, "-c", raw, str(socket), approval_id]).returncode == 0

        for name in ("authority.db", "checkpoint.seed", "binding.json"):
            for mode in ("rb", "wb"):
                result = run_as(AGENT, [sys.executable, "-c",
                    "import sys; open(sys.argv[1],sys.argv[2])", str(state / name), mode])
                assert result.returncode != 0, (name, mode)
        second = run_as(SERVICE, command)
        assert second.returncode != 0, "second daemon acquired active state"

        # Socket squatting cannot impersonate the service to the authenticated client.
        fake = workspace / "fake.sock"
        fake_process = subprocess.Popen([sys.executable, "-c",
            "import socket,sys,time,os; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); "
            "os.chmod(sys.argv[1],0o666); s.listen(); time.sleep(10)", str(fake)],
            user=AGENT, group=AGENT, extra_groups=[])
        try:
            for _ in range(100):
                if fake.exists(): break
                time.sleep(0.01)
            call(OPERATOR, {"method": "status"}, endpoint=fake, ok=False)
        finally:
            fake_process.terminate(); fake_process.wait(timeout=10)

        stop()
        # No automatic unlink, no silent policy/principal reassignment.
        assert run_as(SERVICE, command).returncode != 0
        socket.unlink()
        changed = command.copy(); changed[changed.index(str(OPERATOR))] = str(OUTSIDER)
        assert run_as(SERVICE, changed).returncode != 0
        start()
        assert call(AGENT, {"method": "status"}) == status, "restart reset identity/session/key"
        stop(); socket.unlink()
        state.chmod(0o750)
        assert run_as(SERVICE, command).returncode != 0
        state.chmod(0o700)
        (state / "hostile-link").symlink_to(workspace / "example.txt")
        assert run_as(SERVICE, command).returncode != 0
        print("PASS: cross-account approvals, private state, impersonation, lease bounds and restart binding")
    finally:
        if process is not None:
            process.terminate(); process.wait(timeout=10)
        if log is not None: log.close()
        shutil.rmtree(root)


if __name__ == "__main__":
    main()
