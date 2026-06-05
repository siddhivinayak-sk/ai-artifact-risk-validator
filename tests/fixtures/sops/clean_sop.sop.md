---
title: Code Deployment SOP
version: "1.3"
last_reviewed: "2024-11-01"
owner: platform-team
---

# SOP: Code Deployment Procedure

## Purpose

Standard operating procedure for deploying application code to production environments.

## Prerequisites

- All tests passing in CI pipeline
- Code review approved by at least 2 reviewers
- Change ticket approved in ITSM system

## Procedure

### Step 1: Pre-deployment Checks

1. Verify all automated tests pass
2. Confirm rollback plan is documented
3. Notify on-call team of planned deployment
4. Check system health dashboards

### Step 2: Deploy to Staging

1. Merge feature branch to staging
2. Run integration test suite
3. Verify staging environment health
4. Obtain sign-off from QA team

### Step 3: Deploy to Production

1. Create deployment tag following semver
2. Trigger production deployment pipeline
3. Monitor error rates for 15 minutes
4. Verify key user flows are functional

### Step 4: Post-deployment

1. Update deployment log
2. Close change ticket
3. Notify stakeholders of completion
4. Schedule post-deployment review if needed

## Rollback Procedure

1. Revert to previous deployment tag
2. Trigger rollback pipeline
3. Verify system recovery
4. Document incident details
