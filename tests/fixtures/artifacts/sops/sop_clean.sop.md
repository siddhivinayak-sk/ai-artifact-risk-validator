---
title: Code Deployment SOP
version: "2.0"
author: platform-team
---

# SOP: Standard Code Deployment

## Purpose

Standard procedure for deploying code changes to production environments.

## Prerequisites

- All unit tests passing
- Code review approved by at least two reviewers
- Staging environment validation complete
- Change request ticket created and approved

## Procedure

Step 1: Create a release branch from the main branch
  - Name format: release/vX.Y.Z
  - Tag the commit with the version number

Step 2: Run the full test suite in the CI/CD pipeline
  - Unit tests must pass with 90% or higher coverage
  - Integration tests must pass
  - Security scans must have no critical findings

Step 3: Deploy to staging environment
  - Verify all health checks pass
  - Run smoke tests
  - Monitor error rates for 15 minutes

Step 4: Deploy to production with canary rollout
  - Deploy to 5% of traffic initially
  - Monitor error rates and latency for 30 minutes
  - Gradually increase to 100% if metrics are healthy

Step 5: Post-deployment verification
  - Verify health checks
  - Confirm monitoring dashboards show normal metrics
  - Update the change ticket with completion status

## Rollback Procedure

If any issues are detected:
1. Immediately roll back to the previous version
2. Notify the on-call team
3. Create an incident ticket
4. Conduct post-mortem within 48 hours
