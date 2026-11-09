# Phase delivery plan

Base source: deployed ab65d878b7462ccdd8e64d63721a57b20aac62ae; issue #340.
Preserve the original dirty workspace and the earlier integration worktree.

1. Read-only host capacity and operator-authorized AWS inventory.
2. Generate explicit Terraform resources for observed, approved existing assets.
   Pin CLI/provider, preserve exact cloud policy, prevent_destroy and account/region.
   Export no secrets. Inventory whether EC2 user-data is empty before adopting it.
3. Install verified Terraform tooling outside app runtime. Use isolated operator
   credential_process and protected state; initialize, import and reconcile only
   configuration until plan reports zero changes. Never apply to hide drift.
4. Validate lock behavior, private state permissions/encryption and read-only
   drift detection. Record exclusions and keep H1 incomplete until reproduction
   acceptance exists. Do not call import/no-op a new environment reconstruction.
5. Carry measured CPU/RAM/disk budgets into H4 storage/retention and trace-backend
   design, then H3 and gated H2/G implementation. Do not install all services by guess.

Initial observed host: 2 vCPU, ~7.6 GiB RAM with ~6.7 GiB available, ~5 GiB disk free.
These are idle observations, not safe coexistence/load benchmarks. Keep scanner
reserve and 3 GiB free disk requirement; bound tooling/provider caches separately.
