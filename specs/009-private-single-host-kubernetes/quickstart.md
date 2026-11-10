# Authorized private single-host Kubernetes continuation

Enter through AGENTS, canonical 006, 007 and 008 first. Read spec.md, plan.md
and tasks.md here before implementation. On 2026-11-09 the owner answered
"계속. 한 대로 진행해" to the concrete single-host operating-scope question.
This resolves the 008 scope conflict for this narrower private operation only.
Do not change, claim passed, or synthesize the general 005/006 T053-T056 chain.

The target remains EC2 i-0d24d0502cfc5a9c5, account024139495514, Seoul, one
encrypted50GiB root disk. No extra compute, AWS IAM expansion, public ingress,
registry or cloud mutation. Initial bootstrap leaves the existing app/ingress,
six private migrations and independent gVisor scanner intact. No real scan or
DB restore is needed for control-plane installation.

Execution: review bounded capacity/network/recovery design; validate native
preflight rejection; install vendor-checksummed pinned K3s with private control
ports and separate containerd; verify node and continuing app health. Only then
implement signed-image admission, constrained API/web manifests, GitOps and each
actual strategy/HPA acceptance. Keep rollout switches reversible and preserve
sessions/data. Never count bootstrap as G3, HPA, GitOps or full completion.

For bootstrap-only changes, run Python policy tests and native actual readiness,
network exposure, unchanged-container and HTTP checks. Do not repeat unchanged
workspace/SQL/scanner suites. API/schema/worker changes retain full affected CI
and signed-candidate gates. Record scoped evidence and open tasks. Keep this
entrypoint and parent continuations synchronized.

For issue352's local signed-image import/admission, read admission.md. This keeps
PodSecurity restricted and application traffic unchanged; migration exceptions
are a later separately reviewed implementation step within this approved scope.
