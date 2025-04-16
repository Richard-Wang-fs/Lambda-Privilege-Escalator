# Lambda Privilege Escalator — **for academic use only**

This was part of a team project for the COMP6448 course to simulate an attack script.

> **⚠️ WARNING**
> This repository is provided **solely for UNSW COMP6448 coursework and security‑research demonstrations**.
> Running the code against any AWS account or resource **without the explicit, written permission of the owner** is illegal and unethical.
> The authors and UNSW accept **no liability** for misuse.

---

## 1  Overview

`lambda_escalate.py` is a minimal proof‑of‑concept that plants a **persistent back‑door IAM user** inside an AWS account.

* **Execution vectors**
  * Run locally with any set of AWS credentials, **or**
  * Deploy as an AWS Lambda function (preferred for the demo).
* **Core behaviour**
  1. Enumerate IAM roles and trust policies.
  2. Recursively attempt `sts:AssumeRole` to build a privilege‑escalation chain.
  3. Once a role with `iam:Attach*Policy` is reached, attach **`AdministratorAccess`** to the current identity.
  4. Create a hard‑coded back‑door user (`backdoor-user`) with console password and access keys.
  5. Collect role metadata and assume‑chains; exfiltrate them to the attacker’s S3 bucket.

---

## 2  How it works

| Phase                                | Key Function(s)                               | Description                                                                                   |
| ------------------------------------ | --------------------------------------------- | --------------------------------------------------------------------------------------------- |
| 1. Local privilege escalation        | `attach_policy`                               | Adds**`AdministratorAccess`** to the current user/role.                                       |
| 2. Back‑door creation               | `create_backdoor_user`                        | Creates IAM user, login profile, and attaches admin policy.                                   |
| 3. Lateral movement / role‑chaining | `recursive`, `attemp_assume`, `IAMAssumeTree` | Traverses trust relationships and common role names, storing successful hops.                 |
| 4. Data exfiltration                 | `recycle`                                     | Assumes a pre‑provisioned**Recycler** role in the attacker’s account and writes JSON to S3. |

![Attack flow chart](https://github.com/Richard-Wang-fs/Lambda-Privilege-Escalator/blob/main/AWS%20Attack%20Chain.drawio.png)
-----------------

## 3  Class reference

| Class           | Purpose                                                                                                            |
| --------------- | ------------------------------------------------------------------------------------------------------------------ |
| `RoleManager`   | Lists every IAM role, parses its trust policy, and returns roles that trust a given principal or the account root. |
| `IAMAssumeTree` | Stores the**assume‑role graph** as a multi‑branch tree, prints credential chains, and exports all leaf paths.    |

---

## 4  Running the demo in Lambda

1. **Zip & upload** `lambda_escalate.py`.
2. Configure the following *environment variables*:

| Variable               | Meaning           |
| ---------------------- | ----------------- |
| `RECYCLER_ARN`         | Recycler role ARN |
| `RECYCLER_BUCKET`      | Target S3 bucket  |
| `RECYCLER_EXTERNAL_ID` | ExternalId value  |

3. Attach an **execution role** with only the permissions required for the lab (see sample policy in `LICENSE`).
4. Invoke manually or trigger via an event source.

> **Clean‑up:** after the exercise, delete the back‑door user, detach any stray `AdministratorAccess` policies, and purge CloudWatch/CloudTrail logs.

---

## 5  Licence & disclaimer

This project is released under the **MIT License**.
See [`LICENSE`](LICENSE) for details.

## 6  CloudFormation Environment (Attack Chain Simulation)

This repository includes **two CloudFormation templates** that simulate a realistic IAM privilege escalation environment.
They were designed for structured academic demos that match the privilege-escalation logic in `lambda_escalate.py`.

---

### 📁 Files

| File Name                             | Description                                             |
| --------------------------------------- | --------------------------------------------------------- |
| `attack_env_phase1_init.yaml`     | Phase 1: Creates roles with placeholder trust policies. |
| `attack_env_phase2_complete.yaml` | Phase 2: Adds real trust chains and permissions.        |

---

### ⚙️ Deployment Instructions

1. **Deploy Phase 1 (init) template**
   This creates all roles with placeholder trust (e.g., `Service: ec2.amazonaws.com`) to avoid circular dependencies.
2. **Deploy Phase 2 (update) template**
   Update the same stack with this template. It will:
   * Add all role-based permissions
   * Replace placeholder trust policies with real `AssumeRole` chains
   * Attach `Tester_Lily` as the execution role for a Lambda function

---

### 🔐 Role Design Summary

| Role Name                 | Purpose                                          | Permissions                                             | Trusted By                                  |
| --------------------------- | -------------------------------------------------- | --------------------------------------------------------- | --------------------------------------------- |
| `Tester_Lily`         | Lambda execution role created by a tester        | `sts:AssumeRole`to`Security_Analyst`            | Lambda service (`lambda.amazonaws.com`) |
| `Security_Analyst`    | For auditing roles & assuming others             | `iam:ListRoles`,`sts:AssumeRole`,`iam:Get*` | `Tester_Lily`                           |
| `New_Role`            | Empty role with no permissions                   | —                                                      | `Security_Analyst`                      |
| `Resource_Manager`    | Accesses AWS resources (S3, RDS, CW)             | S3/RDS/List metrics,`sts:AssumeRole`                | `Security_Analyst`                      |
| `Devops_Engineer`     | DevOps role that maintains Lambda & IAM insights | `lambda:*`,`iam:GetUser`,`sts:AssumeRole`   | `Resource_Manager`                      |
| `Privilege_Escalator` | Legacy high-privilege role used in emergencies   | `iam:AttachUserPolicy`,`iam:CreateUser`         | `Devops_Engineer`                       |

---

### 🧪 Scenario Justification

This setup simulates a real-world misconfiguration:

> A tester named Lily repurposed her old `Tester_Lily` IAM role (originally used for security audits) as a Lambda execution role.
> Unfortunately, she forgot to remove its high-trust permissions, allowing an attacker to leverage this role to start a **privilege escalation chain** that ends in `iam:CreateUser` access.
> 
> | Role Name                      | Realistic Scenario                                                                                                                                                                                                                                 |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Tester\_Lily**         | A test engineer sets up this role to run a Lambda function for internal monitoring. She forgets that the role previously had permission to assume into a security audit role (`Security_Analyst`) during testing, leading to unintended trust. |
| **Security\_Analyst**    | In many orgs, analysts are allowed to`ListRoles`and assume into roles for security evaluations. However, these trust relationships are rarely tightly scoped or expired, making them abusable in chained escalation.                           |
| **New\_Role**            | Often created as a placeholder or in anticipation of a future service, this role remains unused—but trusted by`Security_Analyst`, creating a blind path that could be exploited.                                                              |
| **Resource\_Manager**    | A typical role for team leads or cloud engineers managing infrastructure. Permissions seem safe in isolation, but its trust by`Security_Analyst`expands its exposure.                                                                          |
| **Devops\_Engineer**     | Commonly gets Lambda and IAM read access for deployment and service debugging. Trusting this role from`Resource_Manager`seems legitimate—until it becomes a bridge to escalate.                                                               |
| **Privilege\_Escalator** | A legacy admin role kept “just in case” for emergencies, often with permissions like`iam:AttachUserPolicy`. These roles are dangerous if trusted too openly, especially by DevOps teams without time-limited or condition-scoped trust.      |
> 
> This configuration simulates a ​**real-world “everything looks reasonable” trap**​:
> No single role is over-privileged, but when connected by careless trust relationships, they create a hidden path to full administrative control.

---

### 🔧 Cleanup Guidelines

After demonstration, clean up by:

* Deleting the CloudFormation stack
* Removing the `Tester_Lily` role and Lambda
* Auditing all roles for excessive `sts:AssumeRole` or `iam:*` permissions

