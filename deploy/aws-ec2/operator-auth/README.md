# Maintained operator authentication

The owner explicitly requested maintained login and no repeated manual prompts.
Use the existing IAM user only. No new access keys, IAM policies, app/CI secret
values or runtime-role permissions are created. AWS login has an absolute maximum
session duration; a keepalive cannot override it. Native CLI credential_process
refreshes short-lived credentials; the local broker reauthorizes through the
existing account when needed, rather than pretending the token never expires.

Install check.py as root-only operator/operator-auth-check.py and run a five-minute
systemd check. Keep the login cache root0700/files0600 on the encrypted disk. The
application continues using its existing auto-rotating EC2 instance credentials.

The local Windows broker uses existing Chrome and pinned playwright-core1.65.0.
Keep config, browser profile, state and the DPAPI-encrypted supplied credential in
a current-user-only directory outside Git. decrypt.ps1 returns plaintext only to
the local broker's captured pipe. No password/code/exception detail is logged.
No browser password manager or long-lived IAM access key is used. Register as the
current Windows user with limited privileges, not SYSTEM/admin. On MFA, changed
pages/credentials or wrong identity, fail closed and back off; do not bypass it.

Use --once for the existing authenticated path and --renew-once to verify actual
unattended reauthorization. Keep the ephemeral tailnet handoff closed afterward.
This is operator maintenance, not application onboarding or general qualification.

https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sign-in.html

Installed evidence (2026-11-10 UTC): existing exact IAM identity verified on
server; --renew-once completed unattended through official AWS login; encrypted
credential decryption validated without outputting values; current-user scheduled
task AegisAI-OperatorAuthentication running; root five-minute refresh timer active.
The private handoff closes after reauthorization. Browser profile/config/ciphertext
remain outside this repository. Server cache remains root-only.

The Windows account must be logged in and its PC/Tailscale online for automatic
reauthorization. Server refresh continues independently while its AWS session is
refreshable. This does not promise authentication through account revocation,
new MFA requirements or a powered-off operator PC. Application EC2-role refresh
is independent and is not replaced by this operator session.
