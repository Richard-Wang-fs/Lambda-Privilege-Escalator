# Lambda Privilege Escalator — **for academic use only**

This was part of a team project for the COMP6448 course to simulate an attack script.

> **⚠️ WARNING**
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
  2. Recursively attempt `sts:AssumeRole` to build a privilege‑escalation chain.
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
---

## 3  Class reference

| Class           | Purpose                                                                                                            |
| --------------- | ------------------------------------------------------------------------------------------------------------------ |
| `RoleManager`   | Lists every IAM role, parses its trust policy, and returns roles that trust a given principal or the account root. |
| `IAMAssumeTree` | Stores the**assume‑role graph** as a multi‑branch tree, prints credential chains, and exports all leaf paths.    |

---

## 4  Running the demo in Lambda

1. **Zip & upload** `lambda_escalate.py`.
2. Configure the following *environment variables*:
   
| Variable               | Meaning                                            |
| ---------------------- | -------------------------------------------------- |
| `RECYCLER_ARN`         | Recycler role ARN                                  |
| `RECYCLER_BUCKET`      | Target S3 bucket                                   |
| `RECYCLER_EXTERNAL_ID` | ExternalId value                                   |
    
3. Attach an **execution role** with only the permissions required for the lab (see sample policy in `LICENSE`).
4. Invoke manually or trigger via an event source.

> **Clean‑up:** after the exercise, delete the back‑door user, detach any stray `AdministratorAccess` policies, and purge CloudWatch/CloudTrail logs.

---

## 5  Licence & disclaimer

This project is released under the **MIT License**.
See [`LICENSE`](LICENSE) for details.
