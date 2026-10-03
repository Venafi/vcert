# Collaboration & Progress Log: CyberArk Certificate Manager & VCert

This living document tracks customer feedback, technical discoveries, architecture decisions, code releases, and communications between **Tal** and **Robert**.

---

## 👥 Stakeholders & Environment

| Role | Name | Details |
|---|---|---|
| **Author / Lead** | **Tal** | Leads engineering, architecture, and customer enablement for VCert & CyberArk integration. |
| **Customer Partner** | **Robert** | Senior Infrastructure Engineer evaluating CyberArk Certificate Manager SaaS (VAAS) for load-balanced Linux/Nginx clusters. |
| **Primary Test Environment** | `ue1ailxngxas001` | Linux enterprise host running Nginx with automated certificate playbooks. |
| **Primary Directive** | **Comfort & Confidence** | *"My only goal is to make Robert comfortable with the platform -- remember that! Any communication we have with him must follow this goal!"* |

---

## 📅 Chronological Interaction Timeline

### Entry 1: Multi-Node Load Balancer Sharing (`pickupFirst`)
- **Origin**: GitHub Issue #649.
- **Problem Statement**:
  - In a clustered Nginx deployment, multiple nodes share the same VIP/certificate.
  - Node 1 enrolls a certificate.
  - Node 2 ran playbook and enrolled a duplicate cert with a different private key.
- **Solution**:
  - Implemented `pickupFirst: true` across TPP, NGTS, and CyberArk Certificate Manager SaaS (`vcp`).
  - Follower nodes inspect the platform first, download the existing certificate + server-generated key (`csr: service`), and skip duplicate enrollment.

---

### Entry 2: Retired Certificate Edge Case Discovery
- **Robert's Report on `ue1ailxngxas001`**:
  - Robert retired a certificate in CyberArk and ran `sudo /usr/local/bin/vcert run -f ~/playbook.yaml`.
  - VCert output: `certificate in good health. No actions needed`.
  - Robert observed: *"It didn’t generate the new cert after retirement. So if I wanted to go zero touch I would have to setup the cron job with force-renew and it will generate a new cert daily, or I would need to make sure the initial cert and key files are deleted as part of the afterInstallAction... I think going this direction would keep CyberArk authoritative for the environment and aligns better with NIST recommendations."*
- **Root Cause Analysis**:
  - `pickupFirst` correctly saw that CyberArk returned 0 active certs (`!loc.Found`) and fell through to standard enrollment.
  - However, standard enrollment called `isCertificateChanged()`, which only checked if the local cert file on disk was nearing expiration. Since the local file had a future expiration date, it concluded "good health".
  - Robert's enterprise intuition was 100% correct: CyberArk must be the central authority of truth.

---

### Entry 3: Contract 001 Formalization
- **Action**: Created [`BACKLOG.md`](BACKLOG.md) defining **Contract 001: Central Platform Authority & Zero-Touch Reconciliation**.
- **Key Rules**:
  1. Under `pickupFirst: true`, CyberArk's state is authoritative over local filesystem cache.
  2. If local files exist on disk, but CyberArk has zero active certificates (due to retirement or revocation), the local certificate is categorized as **unauthorized**.
  3. VCert bypasses local file expiration dates and immediately triggers an authoritative replacement enrollment and installation.
  4. Completely eliminates the need for `--force-renew` cron workarounds or manual file deletion scripts.
- **Compliance**: Aligned directly with NIST SP 800-52 and SP 800-57 central lifecycle management guidelines.

---

### Entry 4: Visual Architecture (`tldraw-flow`)
- **Action**: Designed an interactive, light-themed state machine diagram visualizing the 5-way decision engine and zero-touch reconciliation.
- **Artifacts**:
  - Native editable file: [`vcert-pickupfirst-flow.tldr`](vcert-pickupfirst-flow.tldr)
  - Standalone HTML preview: [`vcert-pickupfirst-flow.html`](vcert-pickupfirst-flow.html)

---

### Entry 5: Implementation & Release `v5.13.12-pickupFirst`
- **Code Changes**:
  - [`pkg/playbook/app/service/pickup_first.go`](pkg/playbook/app/service/pickup_first.go): Added Contract 001 detection branch; added cryptographic key-matching validation (`keyMatchesCert`).
  - [`pkg/playbook/app/service/service.go`](pkg/playbook/app/service/service.go): Extracted `executeEnrollmentAndInstall()` helper for direct authoritative invocation.
- **Cross-Platform Compilation**:
  - Built all 8 architectures (`linux_amd64`, `linux_arm64`, `linux_386`, `windows_amd64`, `windows_386`, `windows_arm64`, `darwin_amd64`, `darwin_arm64`).
- **GitHub Release**:
  - Published to [`tall27/vcert-pickupFirst: v5.13.12-pickupFirst`](https://github.com/tall27/vcert-pickupFirst/releases/tag/v5.13.12-pickupFirst).
  - Pushed to Upstream PR #688 branch (`tall27/vcert:add-pickup-first-mode`).

---

### Entry 6: Documentation Sync (`pickup_first_guide.html`)
- **Action**: Audited the local [`pickup_first_guide.html`](pickup_first_guide.html) against the implementation.
- **Updates**:
  - Expanded 4-way decision table to the **5-Way Decision Engine** including Contract 001 and Cryptographic Key Matching.
  - Added support documentation for CyberArk Certificate Manager SaaS (`vcp`).
  - Committed and pushed to GitHub.

---

### Entry 7: Comprehensive Unit Test Suite
- **Action**: Implemented 10 deterministic scenario tests in [`pkg/playbook/app/service/pickup_first_test.go`](pkg/playbook/app/service/pickup_first_test.go):
  1. `TestPickupFirst_Contract001_AuthoritativePlatformState_RetiredCert`: **PASS**
  2. `TestPickupFirst_LeaderNode_EmptyDisk_PlatformNotFound`: **PASS**
  3. `TestPickupFirst_Match_DefersToRenewBefore`: **PASS**
  4. `TestPickupFirst_RefuseDowngrade`: **PASS**
  5. `TestPickupFirst_KeyMismatch_AutoEnrolls`: **PASS**
  6. `TestPickupFirst_DiskKeyMatches_InstallsSuccessfully`: **PASS**
  7. `TestPickupFirst_PlatformNewer_VaultedKey_InstallsSuccessfully`: **PASS**
  8. `TestPickupFirst_Disabled`: **PASS**
  9. `TestPickupFirst_ForceRenew`: **PASS**
  10. `TestPickupFirst_LocatorErrors`: **PASS**
- **Result**: 100% test pass across all packages (`go test ./pkg/playbook/...`).

---

### Entry 8: ACME / `lego.exe` Analysis & Combined Communication
- **Questions Addressed**:
  1. *What if an external tool like `lego.exe` issues a cert with a client CSR (no private key in CyberArk)?*
     - If local disk has matching key: `vcert` binds it and skips duplicate enrollment.
     - If local disk lacks matching key: `vcert` detects mismatch and triggers an authoritative replacement enrollment to prevent web server downtime (`key values mismatch`).
  2. *Can `lego` or `certbot` use Venafi for server-side key generation?*
     - No. The ACME standard (RFC 8555) by design requires client-side key generation. Server-side key vaulting is unique to CyberArk/Venafi native REST APIs (`vcert` with `csr: service`).
- **Communication**: Sent concise combined response to Robert signed by **Tal**.

---

## 📌 Open Action Items & Verification
- [ ] Await Robert's test run of `vcert v5.13.12-pickupFirst` on `ue1ailxngxas001` with retired cert scenario.
- [ ] Monitor Upstream PR #688 review and CI checks on `Venafi/vcert`.
