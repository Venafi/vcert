# Backlog: Feature Contracts & Architectural Specifications

## Contract 001: Authoritative Platform State & Zero-Touch Revocation/Retirement Reconciliation in `pickupFirst` Mode

* **Status**: Approved / In Backlog
* **Component**: `pkg/playbook/app/service` (`pickup_first.go`, `service.go`)
* **Reference Issue**: [GitHub Issue #649](https://github.com/Venafi/vcert/issues/649)
* **Design Stakeholder**: Robert Fults / Enterprise Architecture & NIST Alignment

---

### 1. Architectural Intent & Problem Statement

In standard standalone PKI operations, an endpoint agent inspects only its local filesystem (`NotAfter` timestamp on `/etc/nginx/ssl/cert.pem`) to evaluate whether a certificate requires renewal. 

However, in **`pickupFirst: true`** mode, the connected enterprise trust platform (**CyberArk Certificate Manager SaaS / Venafi Cloud**, **Palo Alto Networks NGTS**, or **Venafi TPP**) is explicitly designated as the **Authoritative Source of Truth** for certificate lifecycle state, directly aligning with **NIST SP 800-52, 800-57, and 800-185** guidelines for centralized cryptographic governance.

#### The Problem / Defect
When a security administrator **retires** or **revokes** a certificate on the authoritative central platform:
1. `pickupFirst` searches the platform and correctly observes that no active, valid certificate exists (`loc.Found == false`).
2. `pickupFirst` falls through to the standard enrollment flow.
3. Legacy `service.go` invokes `isCertificateChanged()`, which only queries the local disk's `NotAfter` date.
4. Because the local certificate on disk may not expire for months or years (e.g. 2027), `isCertificateChanged()` falsely concludes: `certificate in good health. No actions needed`.
5. **Defect Outcome**: The endpoint continues running an orphaned, untrusted, or retired certificate indefinitely, unless an operator manually runs `--force-renew` or deletes the local file. This breaks true zero-touch automation and violates centralized authority.

---

### 2. Formal State Decision Contract

Let:
* **$C_{local}$**: Certificate currently installed on disk (`inst.File`).
* **$T_{local}$**: SHA-1 thumbprint of $C_{local}$ ($None$ if file is missing or unreadable).
* **$Exp_{local}$**: Expiration timestamp (`NotAfter`) of $C_{local}$.
* **$C_{platform}$**: Newest certificate returned by `LocateLatestCN` where $Status \in \{ACTIVE, ISSUED\}$ and $Status \notin \{RETIRED, REVOKED\}$.
* **$T_{platform}$**: SHA-1 thumbprint of $C_{platform}$ ($None$ if no active matching certificate exists on the platform).
* **$Exp_{platform}$**: Expiration timestamp (`ValidityEnd`) of $C_{platform}$.

#### State Transition & Action Matrix

| Scenario | Local State ($T_{local}$) | Platform State ($T_{platform}$) | Contract Action | Operational Result | Architectural Rationale |
|:---|:---|:---|:---|:---|:---|
| **S1: Cluster Follower Boot** | $None$ | $T_{platform} \neq None$ | **Pickup & Install** | Downloads $C_{platform} + K_{vault}$, installs to disk. 0 CA enrollments. | Multi-node cluster convergence. |
| **S2: Day 0 Bootstrap** | $None$ | $None$ | **Enroll & Install** | Requests new cert from CA, vaults key, installs locally. | Initial cluster leader rollout. |
| **S3: In-Sync & Healthy** | $T_{local} == T_{platform}$ | $T_{platform} \neq None$, Date healthy | **Fast Exit (No Action)** | Exits in <1s with `certificate in good health`. | Sub-second idempotent daily cron execution. |
| **S4: Routine Expiration** | $T_{local} == T_{platform}$ | Within `renewBefore` window | **Renew / Re-enroll** | Enrolls renewed cert from CA, installs locally. | Standard proactive renewal lifecycle. |
| **S5: Follower Cluster Convergence** | $T_{local} \neq T_{platform}$ | $Exp_{platform} > Exp_{local}$ | **Pickup & Upgrade** | Downloads renewed $C_{platform} + K_{vault}$, updates local disk. 0 CA enrollments. | Follower nodes align with leader renewal. |
| **S6: Downgrade Refusal** | $T_{local} \neq T_{platform}$ | $Exp_{platform} < Exp_{local}$ | **Refuse Downgrade** | Logs warning, leaves local files untouched, exits clean. | Prevents stale replay or rollback attacks. |
| **S7: Authoritative Retirement / Revocation** | $T_{local} \neq None$ | $None$ *(All matching platform certs are RETIRED/REVOKED)* | **Authoritative Re-Enrollment** | **Bypasses local date check**. Enrolls fresh cert from CA, replaces stale local files, triggers service reload. | **NIST Central Authority Compliance**: Retiring a cert in CyberArk forces immediate zero-touch endpoint replacement. |
| **S8: Key Mismatch Protection** | $T_{local} \neq None$ | $T_{platform}$ cert-only (no vault key) | **Verify & Fallback** | Runs `keyMatchesCert`. If local key doesn't match $C_{platform}$, rejects key and enrolls fresh cert + key. | Prevents web server SSL crash (`key values mismatch`). |

---

### 3. Core Contract Guarantees

1. **Zero-Touch Enterprise Automation**:
   * Operators must **never** need to configure cron jobs with `--force-renew`.
   * Operators must **never** script file deletions in `afterInstallAction`.
   * The exact same command (`vcert run -f playbook.yaml`) behaves authoritatively under all circumstances.

2. **Strict Authority Hierarchy**:
   * When `pickupFirst: false`: Local filesystem expiration governs lifecycle (legacy standalone mode).
   * When `pickupFirst: true`: Central platform authorization strictly overrides local filesystem dates. If CyberArk marks a certificate as retired or revoked, the local file is deemed unauthorized regardless of its `NotAfter` date.

3. **Protection Against Transient Network Failures**:
   * An authoritative re-enrollment (Scenario S7) is triggered **only** when the platform explicitly returns search results confirming zero active certificates (or all results have status `RETIRED`/`REVOKED`).
   * If `LocateLatestCN` fails due to network partitions, DNS errors, or HTTP 5xx responses, VCert returns an error and aborts. It **must never** interpret a network failure as a retirement/revocation event.

---

### 4. Implementation Touchpoints

* **`pkg/playbook/app/service/pickup_first.go`**:
  * In `pickupFirstAttempt`:
    ```go
    if (loc == nil || !loc.Found) && foundInstalled {
        zap.L().Info("pickupFirst: installed certificate is not active on authoritative platform (retired/revoked); triggering replacement enrollment",
            zap.String("installed.thumbprint", installedThumb),
        )
        return triggerAuthoritativeEnrollment(config, task)
    }
    ```
* **`pkg/playbook/app/service/service.go`**:
  * Update `isCertificateChanged` or pass authoritative state flag from `pickupFirstAttempt` so the legacy date gate does not short-circuit an authoritative replacement.
* **`pkg/playbook/app/service/pickup_first_test.go`**:
  * Unit test `TestPickupFirst_AuthoritativeRetirementReEnrollment`: Assert that when `foundInstalled == true` and `loc.Found == false`, enrollment is executed and local files are updated.
