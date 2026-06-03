# Research: Production Runtime Infrastructure

## Decisions

### Kubernetes AI Plane first

Define the AI Plane deployment boundary before adding cluster-specific rollout.
This keeps production topology clear while avoiding premature credential and
provider coupling.

### Runtime autoscaling as policy

Autoscaling is modeled as policy driven by latency, queue pressure, provider
health, fallback use, and resource pressure. This avoids tying the product
contract to one autoscaler implementation too early.

### microVM-backed scanner isolation

Scanner provisioning is modeled around stronger-than-pod isolation because scan
jobs fetch customer repositories and run static scanners. The Control Plane and
AI Plane stay outside customer repository execution boundaries.

### Oracle VPS remains dev/demo

The existing Docker Compose path remains useful for development and demos, but it
does not represent the production topology for separated planes or stronger
scan isolation.

## Rejected Alternatives

### Kubernetes cluster provisioning in the first slice

Rejected because this issue is the package skeleton and contract baseline. Live
cluster rollout needs separate secrets, environment decisions, and operational
approval.

### AI Plane receives repository input for convenience

Rejected because 002 and 003 require AI to consume reduced evidence only and
remain advisory-only.

### Pod-only scanner isolation

Rejected because scanner jobs handle fetched customer repositories. The baseline
requires stronger-than-pod isolation before customer repository fetch or scanner
execution.
