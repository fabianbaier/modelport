import assert from "node:assert/strict";
import test from "node:test";
import { buildConnectSshCommand, buildServeSshCommand } from "./ssh.js";

test("serve SSH command binds the reverse listener to hub loopback", () => {
  const command = buildServeSshCommand({
    sshHost: "hub.example",
    sshPort: 2222,
    username: "modelport",
    hubBind: "127.0.0.1:49152",
    upstream: "127.0.0.1:8000"
  });

  assert.equal(command.bin, "ssh");
  assert.ok(command.args.includes("ExitOnForwardFailure=yes"));
  assert.ok(command.display.includes("-R 127.0.0.1:49152:127.0.0.1:8000"));
});

test("connect SSH command rejects public local binds", () => {
  assert.throws(
    () =>
      buildConnectSshCommand({
        sshHost: "hub.example",
        sshPort: 2222,
        username: "modelport",
        localBind: "0.0.0.0:11434",
        openTarget: "127.0.0.1:49152"
      }),
    /local bind must be loopback/
  );
});
