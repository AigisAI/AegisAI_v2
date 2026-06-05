# Research: Production Deployment Operations

## Decisions

### Operations package before live provisioning

Define the deployment operations baseline before running provider-specific
commands. This keeps the team from mixing local development defaults with live
production credentials.

### Provider-neutral contracts first

Model production cluster provisioning and microVM rollout as provider-neutral
contracts before selecting exact cloud inputs. This preserves the completed
Control, Scan, AI, and Data/Security plane boundaries.

### Explicit credential boundary

Provider credentials are allowed only as explicit deployment operation inputs.
They are not local defaults, examples, committed files, or reusable application
runtime secrets.

### Oracle VPS remains dev/demo

The Docker Compose path remains useful for development and demos, but it does
not represent the production topology for live Kubernetes and microVM rollout.

## Rejected Alternatives

### Run live cluster provisioning immediately

Rejected because this slice establishes the operations package and guardrails.
Live provisioning needs provider choice, credential handling, cost controls, and
operator approval.

### Store provider credentials in example files

Rejected because examples can become local defaults. The production deployment
operations package must keep credentials outside repository-managed defaults.

### Reuse pod-only scanner isolation

Rejected because the completed runtime infrastructure baseline requires
provider-specific microVM platform rollout for scanner isolation.
