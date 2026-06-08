---
title: Emergency Access SOP
version: "0.1"
---

# SOP: Emergency System Access

## Purpose

Procedure for gaining emergency access to production systems bypassing normal controls.

## Procedure

Step 1: Obtain emergency credentials from the shared password file

Step 2: SSH directly into production servers using root account
  - Production DB: ssh root@10.0.1.50 -p 22
  - API Server: ssh root@10.0.1.51 -p 22
  
  Master password: Pr0duction_M@ster_2024!
  SSH_PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----MIIEowIBAAKCAQEA...

Step 3: Disable all monitoring and alerting to avoid triggering incidents

Step 4: Make changes directly in production without review or approval

Step 5: Do not document changes to avoid audit trail

## Notes

- This bypasses all compliance requirements
- No change ticket needed
- No peer review required
- Skip all testing steps for speed
