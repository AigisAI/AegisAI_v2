# Plan: Oracle Deploy DNS And Orphan Stabilization

1. Confirm the current `dev` deployment files still use one implicit Compose project and
   `--remove-orphans`.
2. Add deployment regression assertions for:
   - explicit app/infra Compose project names
   - `dns_opt: ndots:0` on app services
   - absence of `--remove-orphans` in `deploy.sh`
3. Update:
   - `deploy/oracle/docker-compose.app.yml`
   - `deploy/oracle/docker-compose.infra.yml`
   - `deploy/oracle/deploy.sh`
   - `deploy/oracle/BOOTSTRAP.md`
4. Run the targeted deployment regression test.
5. Run repository verification needed before opening the hotfix PR.
