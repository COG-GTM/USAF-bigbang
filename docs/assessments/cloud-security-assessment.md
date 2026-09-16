# Cloud security assessment of the Big Bang default configuration

Static assessment of the security posture produced by the Big Bang umbrella chart when installed with
its shipped defaults, measured against the DISA Kubernetes Security Technical Implementation Guide
(V-2 series rule identifiers), NIST SP 800-53 Revision 5, and the DoD Zero Trust pillars. This report is
delivered in the pattern of a Cloud Security Assessment Report CDRL: findings are evidence-backed,
severity-rated, mapped to controls, and assigned to the party that can close them.

The tables and counts in this document are generated from
[`cloud-security-findings.json`](cloud-security-findings.json) by
[`build_assessment_summary.py`](build_assessment_summary.py); the JSON file is the single source of truth
for finding content, and [`test_assessment.py`](test_assessment.py) verifies that the two stay in
agreement and that every evidence reference resolves to a real file and line in this repository.

## 1. Scope and method

### 1.1 Assessed version

<!-- BEGIN GENERATED: metadata -->
| Item | Value |
| --- | --- |
| Repository | `COG-GTM/USAF-bigbang` |
| Base branch | `master` |
| Assessed commit | `6cfe27bd704eba732f795045ae5d0dd86e84e0ff` |
| Umbrella chart version | `3.32.0` |
| Assessment date | 2026-09-16 |
| Distinct findings | 48 |
| Distinct evidence references | 134 |
| Distinct files cited | 29 |
<!-- END GENERATED: metadata -->

### 1.2 Scope

The assessment covers the configuration that the umbrella chart renders when a tenant supplies no
overrides, plus the package integration templates that translate umbrella values into package values.
In scope:

- `chart/values.yaml`: the public values contract and every shipped default.
- `chart/templates/**`: shared helpers (`_helpers.tpl`), the Istio control plane and gateway
  templates, the Kyverno policy and Gatekeeper constraint values, the monitoring, Grafana, Loki, Alloy,
  Tempo, NeuVector, Twistlock, Velero, Keycloak, authservice, Vault, Kiali, and metrics-server
  integration values, and the Secret-rendering templates for registry, Git, SSO, and Grafana credentials.
- `chart/ingress-certs.yaml` and `docs/reference/scripts/quickstart.sh`, because the evaluation
  workflow applies them and they shape what a first deployment looks like.
- `docs/concepts/security-model.md`, `docs/concepts/encryption.md`, `docs/concepts/architecture.md`,
  `docs/configuration/default-credentials.md`, `docs/configuration/network-policies.md`,
  `docs/configuration/gateways.md`, `docs/getting-started/prerequisites.md`, and
  `docs/configuration/production-considerations/*.md`, which define the intended posture and the
  responsibilities Big Bang assigns to the platform owner.

Out of scope: the package charts themselves (independently versioned in their own repositories), the
Kubernetes distribution, node operating systems, the cloud account, and any live cluster. No cluster was
contacted and no chart, values, or package configuration was modified. Where a finding depends on a
package-chart default that the umbrella values do not override (BB-AUD-003, Loki persistence), the
pinned package chart tag recorded in `chart/values.yaml` was read to confirm the behavior described.

### 1.3 Method

1. Read the files above at the assessed commit and record the exact line of each default, template
   expression, or documentation statement relied upon.
2. Classify each observation as one of:
   - **Insecure by default**: the shipped default weakens or omits a control.
   - **Secure by default; tenant can weaken**: the default is sound, but an ordinary values override
     removes the control with no policy guard.
   - **Documented tenant responsibility**: the repository documentation explicitly assigns the control
     to the platform owner or tenant, and the chart cannot implement it.
3. Map each finding to NIST SP 800-53 Rev 5 controls and, where a Kubernetes STIG rule clearly applies,
   to its V-2 series rule identifier. STIG rules are written for control-plane and node components; a
   rule cited for a platform workload default is marked *analogous* to make that distinction explicit.
   Findings on identity, authentication, and access are additionally tagged with the DoD Zero Trust
   pillar they affect.
4. Rate severity using the scale in section 1.4 and assign an owner: **Platform** (Big Bang
   engineering change), **Tenant** (environment values or cluster configuration), or **Government
   decision** (risk acceptance or architecture selection that must precede engineering work).

### 1.4 Severity scale

| Severity | Meaning in this assessment |
| --- | --- |
| CAT I | Default that directly exposes an administrative interface, credential, or key, or removes a required control with no compensating control. |
| CAT II | Default that materially weakens a required control, or a documented tenant responsibility whose omission would produce a CAT I or CAT II condition. |
| CAT III | Default that reduces defense in depth, degrades evidence quality, or narrows an otherwise sound control. |

## 2. Summary

### 2.1 By severity

<!-- BEGIN GENERATED: severity -->
| Severity | Findings |
| --- | --- |
| CAT I | 2 |
| CAT II | 24 |
| CAT III | 22 |
| **Total** | **48** |
<!-- END GENERATED: severity -->

### 2.2 By classification

<!-- BEGIN GENERATED: classification -->
| Classification | Findings |
| --- | --- |
| Insecure by default | 27 |
| Secure by default; tenant can weaken | 9 |
| Documented tenant responsibility | 12 |
| **Total** | **48** |
<!-- END GENERATED: classification -->

### 2.3 Key observations

- Every CAT I finding is a default administrative credential on an interface that a default install
  publishes through the public gateway with single sign-on disabled (Grafana and NeuVector). Each is
  closed by tenant values, but nothing in the chart forces the change.
- The admission-control baseline is strong where it enforces (registry allow-list, non-root, capability
  drops, image tags, NodePort, namespaces) and weak where it audits (service account token automount,
  required labels) or is disabled (image signatures). The exceptions granted to runtime-security and
  log-collection agents are the largest privileged footprint in the baseline and several are annotated
  in the repository itself as lacking justification.
- Network segmentation is rendered comprehensively but the global CIDR definitions default to the entire
  Internet (`0.0.0.0/0`) for the control plane, VPC, SSO, object storage, and Kafka egress paths, so the
  rendered policies are permissive until a tenant supplies environment CIDRs.
- Encryption in transit inside the cluster depends on the mesh: mTLS is STRICT by default, but
  telemetry endpoints are plaintext HTTP and collectors disable certificate verification, so any
  namespace that leaves the mesh loses confidentiality with no policy objection.
- Audit evidence is collected (pod logs, cluster events, mesh access logs) but is stored in a
  single-replica, filesystem-backed Loki with no retention setting, no SIEM forwarding, and no API-server
  audit log ingestion.
- The documentation is candid about the responsibilities it leaves to the platform owner; the
  "documented tenant responsibility" findings are included so the accreditation package can show each
  one is assigned rather than assumed.

## 3. Findings

Findings are grouped by identifier prefix: `NET` (segmentation and egress), `TLS` (mesh and transport
encryption), `POL` (admission control and pod security), `IAM` (identity and access), `SEC` (secrets and
configuration integrity), `AUD` (audit and logging), `SUP` (supply chain), and `OPS` (recovery).

<!-- BEGIN GENERATED: findings-table -->
| ID | Finding | Evidence (file:line) | STIG rule / 800-53 control | Severity (CAT I/II/III) | Recommended remediation | Owner (Platform vs Tenant vs Government decision) |
| --- | --- | --- | --- | --- | --- | --- |
| BB-NET-001 | **Kubernetes API egress allowed to 0.0.0.0/0** (Insecure by default). networkPolicies.controlPlaneCidr defaults to 0.0.0.0/0. Every package NetworkPolicy that permits Kubernetes API egress therefore permits egress to any address. The Gatekeeper template shows the compensating behavior: when the value is 0.0.0.0/0 only the cloud metadata address 169.254.169.254/32 is excluded. | `chart/values.yaml:171-174`<br>`chart/templates/gatekeeper/values.yaml:70-76` | STIG: V-242410 (analogous)<br>800-53: SC-7, SC-7(5), CM-7 | CAT II | Set networkPolicies.controlPlaneCidr to the /32 (or minimal range) returned by `kubectl get endpoints -n default kubernetes` in the environment values file. | Tenant |
| BB-NET-002 | **VPC egress allowed to 0.0.0.0/0** (Insecure by default). networkPolicies.vpcCidr defaults to 0.0.0.0/0. Packages that use the VPC definition for cloud service access (Vault KMS, DNS) receive unrestricted egress. The values comment recommends private endpoints but the default does not assume them. | `chart/values.yaml:179-183`<br>`chart/templates/gatekeeper/values.yaml:77-82` | STIG: no direct STIG rule<br>800-53: SC-7, SC-7(5) | CAT II | Set networkPolicies.vpcCidr to the VPC or private-endpoint CIDR after provisioning private service endpoints. | Tenant |
| BB-NET-003 | **SSO egress definition allows all destinations and all ports** (Insecure by default). The global egress definition `sso` permits ipBlock 0.0.0.0/0 with no port restriction. Any package NetworkPolicy that references the SSO definition allows unrestricted egress until the tenant narrows it to the identity provider's address space. | `chart/values.yaml:190-196` | STIG: no direct STIG rule<br>800-53: SC-7(5), AC-4 | CAT II | Override networkPolicies.egress.definitions.sso with the identity provider CIDRs and TCP 443 only. | Tenant |
| BB-NET-004 | **Object storage egress allowed to any Internet address on TCP 443** (Insecure by default). The `storage-subnets` egress definition permits 0.0.0.0/0 on TCP 443. Packages that write logs, metrics, traces, or backups to object storage (Loki, Tempo, Mimir, Velero, Thanos) can reach any HTTPS endpoint on the Internet by default. Restricting this depends on whether the program provisions private storage endpoints. | `chart/values.yaml:198-205`<br>`chart/values.yaml:179-182` | STIG: no direct STIG rule<br>800-53: SC-7(5), AC-4, SC-7(4) | CAT II | Decide whether object storage is reached through private endpoints or a controlled egress path, then set storage-subnets to that CIDR set. | Government decision |
| BB-NET-005 | **Kafka egress definition allows any Internet address** (Insecure by default). The `kafka-subnets` egress definition permits 0.0.0.0/0 on TCP 9092 and 9093. The definition is dormant unless a package or tenant NetworkPolicy references it, but any consumer inherits Internet-wide broker egress. | `chart/values.yaml:219-228` | STIG: no direct STIG rule<br>800-53: SC-7(5) | CAT III | Override kafka-subnets with the managed broker CIDRs when Kafka egress is needed; otherwise leave unused and confirm no NetworkPolicy references it. | Tenant |
| BB-NET-006 | **Ingress and datastore definitions default to all RFC 1918 space** (Documented tenant responsibility). The load-balancer-subnets, kubeAPI, redis-subnets, and database-subnets definitions default to 10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16. This allows any private address, including other tenants' networks in a shared enclave, to reach ingress gateways and policy webhooks. The values comments and the Keycloak production guidance instruct tenants to narrow these ranges. | `chart/values.yaml:206-218`<br>`chart/values.yaml:229-239`<br>`chart/values.yaml:244-262`<br>`docs/configuration/production-considerations/keycloak.md:22` | STIG: no direct STIG rule<br>800-53: SC-7, AC-4 | CAT III | Replace each definition with the actual load balancer, control plane, and datastore subnets for the environment. | Tenant |
| BB-NET-007 | **NetworkPolicy enforcement depends on the cluster CNI** (Documented tenant responsibility). Global NetworkPolicies are enabled, but the chart can only render policy objects; enforcement depends on a CNI that implements NetworkPolicy. The security model and network policy guidance state this dependency explicitly. A cluster without an enforcing CNI silently accepts every rendered policy while enforcing none. | `chart/values.yaml:168-170`<br>`docs/concepts/security-model.md:35`<br>`docs/configuration/network-policies.md:7-9` | STIG: no direct STIG rule<br>800-53: SC-7, CM-6 | CAT II | Record the CNI and its NetworkPolicy support in the system security plan and verify enforcement with a denied-connection test during accreditation. | Tenant |
| BB-NET-008 | **Ingress gateway egress permitted to every in-cluster service** (Insecure by default). The shared gateway ingress NetworkPolicy helper renders an egress rule with the wildcard `'*': true`, allowing the ingress gateway pods to initiate connections to any pod in the cluster. Gateway compromise therefore yields a full east-west pivot at Layer 3/4; only Istio AuthorizationPolicies (disabled by default, see BB-NET-009) would constrain it. | `chart/templates/_helpers.tpl:1233-1237` | STIG: no direct STIG rule<br>800-53: SC-7, SC-7(21) | CAT III | Enable Istio hardened mode so AuthorizationPolicies restrict gateway-to-service traffic, or add per-package ingress policies that name the gateway as the only permitted source. | Platform |
| BB-NET-009 | **Istio hardened mode (Sidecar, ServiceEntry, AuthorizationPolicy generation) disabled by default** (Insecure by default). Istio hardening is derived from istiod.values.hardened.enabled, which is not set in chart/values.yaml and defaults to false in the helpers. As a result package Sidecar resources, ServiceEntry egress restriction, and AuthorizationPolicy generation from NetworkPolicies are all off unless the tenant opts in. | `chart/templates/istiod/values.yaml:15`<br>`chart/templates/_helpers.tpl:1114-1124` | STIG: no direct STIG rule<br>800-53: SC-7(21), AC-3, AC-4 | CAT II | Set istiod.values.hardened.enabled: true in environment values and validate each package's generated AuthorizationPolicies against the integration test suite. | Platform |
| BB-TLS-001 | **Public gateway TLS server has no explicit minimum protocol version or cipher suites** (Secure by default; tenant can weaken). The default public gateway terminates TLS in SIMPLE mode with credentialName public-cert and does not set minProtocolVersion or cipherSuites. The effective policy is the Istio proxy default rather than a chart-pinned FIPS or TLS 1.2+ profile, and a tenant gateway override can lower it without triggering any policy. | `chart/templates/istio-gateway/_defaults.tpl:14-22`<br>`docs/configuration/gateways.md:46-47` | STIG: V-242418 (analogous); V-242438 (analogous)<br>800-53: SC-8, SC-8(1), SC-13 | CAT III | Pin tls.minProtocolVersion: TLSV1_2 (or TLSV1_3) and an approved cipherSuites list on every gateway server, and add a Kyverno rule that rejects Gateway resources without them. | Platform |
| BB-TLS-002 | **Development domain and a committed development TLS private key are used by evaluation workflows** (Documented tenant responsibility). The default domain is dev.bigbang.mil and the repository contains chart/ingress-certs.yaml, a values file holding an RSA private key and certificate for the public gateway. The quickstart script applies this file automatically. Any deployment that carries the evaluation values forward serves production traffic with a private key that is public in this repository. | `chart/values.yaml:2`<br>`chart/ingress-certs.yaml:5-9`<br>`docs/reference/scripts/quickstart.sh:124`<br>`docs/getting-started/prerequisites.md:18` | STIG: no direct STIG rule<br>800-53: SC-12, SC-17, IA-5(2) | CAT II | Issue the public gateway certificate from the program PKI, supply it as a SOPS-encrypted Secret, set domain to the accredited FQDN, and never include chart/ingress-certs.yaml in production values. | Tenant |
| BB-TLS-003 | **Mesh mTLS defaults to STRICT but can be set PERMISSIVE per package** (Secure by default; tenant can weaken). The metrics helper treats istio.mtls.mode as STRICT when unset, confirming STRICT is the platform default. Any package can set istio.mtls.mode: PERMISSIVE in its values, and packages outside the mesh (documented historically for Grafana, Prometheus, and Alertmanager) receive unencrypted traffic from the gateway. No policy rejects a PERMISSIVE PeerAuthentication. | `chart/templates/_helpers.tpl:1150-1154`<br>`docs/concepts/architecture.md:142-144` | STIG: no direct STIG rule<br>800-53: SC-8, SC-8(1), SC-23, IA-3 | CAT II | Add a Kyverno policy that denies PeerAuthentication resources with mode PERMISSIVE or DISABLE outside an approved exception list, and require Istio injection or ambient enrollment for every tenant namespace. | Tenant |
| BB-TLS-004 | **Prometheus and Alloy scrape targets over mTLS with certificate verification disabled** (Insecure by default). When STRICT mTLS is active, the monitoring, Grafana, and Alloy templates present the Istio workload certificate but set insecureSkipVerify: true. The inline comments explain that Prometheus does not support Istio security naming. Traffic is encrypted but the collector does not authenticate the server identity. | `chart/templates/monitoring/values.yaml:240-247`<br>`chart/templates/monitoring/values.yaml:327-335`<br>`chart/templates/grafana/values.yaml:99-106`<br>`chart/templates/alloy/values.yaml:183-189` | STIG: no direct STIG rule<br>800-53: SC-8, SC-23, IA-3 | CAT III | Document the compensating control (SPIFFE identity enforced by the receiving sidecar) in the SSP, and track upstream support for SPIFFE-aware verification so insecureSkipVerify can be removed. | Platform |
| BB-TLS-005 | **In-cluster telemetry endpoints are plaintext and rely on the mesh for encryption** (Secure by default; tenant can weaken). Alloy writes to Loki over http://, sends traces to Tempo with tls.insecure: true, and falls back to plain HTTP remote-write when sidecar injection is absent. Grafana data sources and the Flux Grafana notification provider also use http:// service URLs. Confidentiality of logs, traces, and metrics in transit exists only while the namespaces are enrolled in the mesh with STRICT mTLS. | `chart/templates/alloy/values.yaml:39`<br>`chart/templates/alloy/values.yaml:169-178`<br>`chart/templates/alloy/values.yaml:190-192`<br>`chart/templates/grafana/values.yaml:170`<br>`chart/templates/grafana/values.yaml:228`<br>`chart/templates/grafana/flux/provider.yaml:14` | STIG: no direct STIG rule<br>800-53: SC-8, SC-8(1) | CAT III | Keep logging, monitoring, tempo, and grafana namespaces mesh-enrolled with STRICT mTLS and add a Kyverno rule that blocks disabling istio.enabled for those packages without a documented exception. | Platform |
| BB-TLS-006 | **cert-manager is enabled with no issuers configured** (Documented tenant responsibility). cert-manager is enabled by default but both bundled issuers (self-signed and Let's Encrypt) are disabled, and no ClusterIssuer is rendered. Certificate lifecycle for gateways and packages is therefore entirely the tenant's responsibility, and there is no automated renewal path until an issuer is configured. | `chart/values.yaml:1340-1342`<br>`chart/values.yaml:1373-1377` | STIG: no direct STIG rule<br>800-53: SC-12, SC-17 | CAT III | Configure a ClusterIssuer backed by the program CA (ACME, Vault, or CA key pair) and monitor Certificate expiry through the bundled Prometheus rules. | Tenant |
| BB-TLS-007 | **Istio CNI disabled, so sidecar injection uses a privileged istio-init container** (Insecure by default). istioCNI is disabled by default. In sidecar mode every injected pod therefore runs an istio-init container that requires NET_ADMIN and NET_RAW to program iptables, and the default security context policy explicitly excludes istio-init. Enabling Istio CNI removes this per-pod privilege. | `chart/values.yaml:274-276`<br>`chart/templates/kyverno-policies/values.yaml:438-441` | STIG: no direct STIG rule<br>800-53: AC-6, CM-7, CM-7(1) | CAT III | Enable istioCNI so traffic redirection is performed by the node-level CNI plugin and remove the istio-init exclusion. | Platform |
| BB-TLS-008 | **Ambient data plane is opt-in and enlarges the pod security exception set when enabled** (Secure by default; tenant can weaken). Ambient mode is off by default. Enabling it activates ztunnel exceptions to the non-root, capability, hostPath, and volume-type policies and a Gatekeeper host filesystem exception. The choice between sidecar and ambient data planes changes the accepted privilege set for the mesh and is an architecture decision, not a values tweak. | `chart/values.yaml:5-11`<br>`chart/templates/kyverno-policies/values.yaml:13-58`<br>`chart/templates/gatekeeper/values.yaml:127-130` | STIG: no direct STIG rule<br>800-53: AC-6, CM-7, SC-8 | CAT III | Select the data-plane mode during architecture review, record the corresponding exception set in the SSP, and re-run the policy exception review whenever the mode changes. | Government decision |
| BB-POL-001 | **Service account token automount policy runs in Audit mode** (Insecure by default). The disallow-auto-mount-service-account-token policy is enabled but set to validationFailureAction: Audit, so workloads that mount API credentials are reported rather than rejected. A mutation policy disables automount on the default ServiceAccount of a fixed list of platform namespaces, which is a partial compensating control that does not cover tenant namespaces. | `chart/templates/kyverno-policies/values.yaml:255-257`<br>`chart/templates/kyverno-policies/values.yaml:1022-1053` | STIG: no direct STIG rule<br>800-53: AC-6, AC-6(10), IA-5, CM-6 | CAT II | Move the policy to Enforce after remediating the reported platform pods and extend the automount mutation to all tenant namespaces. | Platform |
| BB-POL-002 | **Container image signature verification is disabled** (Insecure by default). require-image-signature is disabled and, if enabled, defaults to Audit. Provenance therefore rests on the registry allow-list alone. The security model states that presence in a registry is not proof of provenance or vulnerability compliance. Enabling verification requires the program to select trusted signing keys or a keyless trust root. | `chart/templates/kyverno-policies/values.yaml:405-407`<br>`docs/concepts/security-model.md:47-49` | STIG: no direct STIG rule<br>800-53: SI-7, SI-7(1), CM-14, SR-4(4) | CAT II | Enable require-image-signature in Enforce mode with the Iron Bank public key (or program signing key) as the trust root, after confirming every deployed image is signed. | Government decision |
| BB-POL-003 | **Required workload labels are audited, not enforced** (Insecure by default). require-labels is enabled with validationFailureAction: Audit. Workloads without the required app.kubernetes.io labels are admitted, degrading inventory, ownership attribution, and the label-based selectors used by NetworkPolicies and monitoring. | `chart/templates/kyverno-policies/values.yaml:409-415` | STIG: no direct STIG rule<br>800-53: CM-8, CM-8(3) | CAT III | Promote require-labels to Enforce for tenant namespaces once platform packages are conformant. | Platform |
| BB-POL-004 | **Runtime security agents require privileged, host-namespace, and host-path-write exceptions selected by pod name glob** (Insecure by default). NeuVector (enabled by default) is excluded from disallow-privileged-containers, disallow-host-namespaces, and restrict-host-path-write; Twistlock receives the same exceptions when enabled. Exceptions are keyed on pod name patterns such as neuvector-enforcer-pod*, so any pod created in that namespace with a matching name inherits the exception. Gatekeeper's host filesystem constraint mirrors the same list. | `chart/templates/kyverno-policies/values.yaml:125-148`<br>`chart/templates/kyverno-policies/values.yaml:242-251`<br>`chart/templates/kyverno-policies/values.yaml:842-850`<br>`chart/templates/gatekeeper/values.yaml:115-122` | STIG: V-254800 (analogous)<br>800-53: AC-6, CM-7, CM-7(5), SI-4 | CAT II | Formally accept the privileged agent footprint, restrict namespace write access so only the package HelmRelease can create pods in neuvector and twistlock, and prefer label or ServiceAccount selectors over name globs where the policy supports them. | Government decision |
| BB-POL-005 | **Log collectors receive hostPath and SELinux spc_t exceptions** (Insecure by default). Alloy (enabled by default) and Fluent Bit (optional) are excluded from restrict-host-path-mount and restrict-selinux-type so they can read node log directories using the super-privileged spc_t type. Gatekeeper carries a matching host filesystem exception for Alloy. The comments mark several of these exceptions as requiring further justification. | `chart/templates/kyverno-policies/values.yaml:752-770`<br>`chart/templates/kyverno-policies/values.yaml:907-939`<br>`chart/templates/gatekeeper/values.yaml:123-126` | STIG: no direct STIG rule<br>800-53: AC-6, CM-7, AU-9 | CAT III | Confine the collector to read-only mounts of /var/log/pods and /var/log/containers, evaluate a dedicated SELinux type instead of spc_t, and document the residual exception in the SSP. | Platform |
| BB-POL-006 | **Capability-drop policies exclude platform agent pods** (Insecure by default). add-default-capability-drop and require-drop-all-capabilities are enforced, but both exclude NeuVector, Twistlock, and other agent pods by name pattern. Those pods retain their full capability set at admission time. | `chart/templates/kyverno-policies/values.yaml:64-79`<br>`chart/templates/kyverno-policies/values.yaml:351-402` | STIG: no direct STIG rule<br>800-53: AC-6, CM-7 | CAT III | Replace blanket exclusions with an explicit minimal capability allow-list per agent container in the package chart. | Platform |
| BB-POL-007 | **Twistlock, when enabled, runs unconfined AppArmor and host-network defenders** (Secure by default; tenant can weaken). Twistlock is disabled by default. Enabling it adds an exclusion from restrict-apparmor because the defender uses an unconfined profile, an exclusion from disallow-host-namespaces because the defender uses host networking, and a Gatekeeper host filesystem exception. Host networking also bypasses Istio sidecar injection for those pods. | `chart/values.yaml:1266-1268`<br>`chart/templates/kyverno-policies/values.yaml:683-693`<br>`chart/templates/kyverno-policies/values.yaml:129-139`<br>`chart/templates/gatekeeper/values.yaml:137-145` | STIG: V-242414 (analogous)<br>800-53: AC-6, CM-7, SC-7 | CAT III | Deploy only one runtime security agent; if Twistlock is selected, document the unconfined and host-network exceptions and disable NeuVector. | Tenant |
| BB-POL-008 | **Image registry allow-list is enforced but tenant-extensible and excludes gateways** (Secure by default; tenant can weaken). restrict-image-registries is enforced and limited to registry1.dso.mil and registry.dso.mil, and Gatekeeper's allowedDockerRegistries mirrors the list. The allow-list is a plain values array that any environment override can extend, and Istio ingress and egress gateway deployments are excluded because their image is set to `auto`. | `chart/templates/kyverno-policies/values.yaml:885-904`<br>`chart/templates/gatekeeper/values.yaml:97-101` | STIG: no direct STIG rule<br>800-53: CM-14, SI-7, CM-7(5) | CAT II | Treat additions to the registry allow-list as a configuration change requiring change-board approval, and verify the istiod proxy image used for gateway injection is itself sourced from an approved registry. | Tenant |
| BB-POL-009 | **Mutable image tag policy excludes gateway deployments** (Secure by default; tenant can weaken). disallow-image-tags is enforced but excludes istio-gateway pods because the upstream gateway chart pins the image to the `auto` tag and relies on istiod injection. The effective gateway image is therefore determined at runtime by istiod's proxy configuration rather than by a reviewable manifest. | `chart/templates/kyverno-policies/values.yaml:193-209` | STIG: no direct STIG rule<br>800-53: CM-14, CM-2 | CAT III | Record the istiod proxy image and digest as part of the release baseline evidence so the gateway image is traceable despite the auto tag. | Platform |
| BB-POL-010 | **Pod Security Admission is not configured by the chart** (Documented tenant responsibility). The chart relies on Kyverno (and optionally Gatekeeper) for pod security. It does not label namespaces with pod-security.kubernetes.io levels or configure the built-in Pod Security Admission controller. The prerequisites guidance states that admission control must be chosen and configured deliberately and that enabling a policy engine does not guarantee a compliance posture. | `docs/getting-started/prerequisites.md:66-70`<br>`docs/concepts/security-model.md:29-31` | STIG: V-254800; V-254801<br>800-53: CM-6, AC-6, CM-7 | CAT II | Configure Pod Security Admission at the API server (baseline or restricted default with warn/audit for exceptions) as a defense-in-depth layer beneath Kyverno and label platform namespaces accordingly. | Tenant |
| BB-POL-011 | **metrics-server is deployed into kube-system with API credential automount** (Insecure by default). metricsServer defaults to `auto` and, when deployed, installs into the kube-system namespace with automountServiceAccountToken: true. Placing a platform-managed workload in the control-plane namespace mixes user-managed resources with system components and places its credentials outside the platform namespaces covered by the automount mutation policy. | `chart/values.yaml:2160-2162`<br>`chart/values.yaml:2176-2184` | STIG: V-242417 (analogous); V-242383 (analogous)<br>800-53: CM-7, AC-6, SC-7(21) | CAT III | Set metricsServer.values.namespace.name to a dedicated namespace with create: true, or rely on the cluster distribution's metrics-server and set metricsServer.enabled: false. | Platform |
| BB-POL-012 | **Several shipped policy exceptions are annotated as lacking justification** (Insecure by default). The Kyverno policy values contain repeated `NEEDS FURTHER JUSTIFICATION` comments on exceptions for privileged containers, AppArmor, capabilities, hostPath mounts, hostPath writes, and SELinux types. These are risk acceptances embedded in the default baseline without a recorded rationale or approval. | `chart/templates/kyverno-policies/values.yaml:234`<br>`chart/templates/kyverno-policies/values.yaml:686`<br>`chart/templates/kyverno-policies/values.yaml:697`<br>`chart/templates/kyverno-policies/values.yaml:784`<br>`chart/templates/kyverno-policies/values.yaml:847`<br>`chart/templates/kyverno-policies/values.yaml:915-921` | STIG: no direct STIG rule<br>800-53: CM-6, CA-5, RA-3 | CAT III | Replace each annotation with a reference to an approved exception record (ticket or SSP appendix) that names the risk owner and review date. | Platform |
| BB-IAM-001 | **Single sign-on is disabled for every enabled administrative interface** (Insecure by default). Kiali, Kyverno Reporter, NeuVector, Tempo, Prometheus/Alertmanager, and Grafana are all enabled by default and exposed through the public gateway, but each package's sso.enabled is false. Authentication therefore falls back to package-local mechanisms (local admin accounts, Kubernetes tokens, or none) rather than the enterprise identity provider with MFA and centralized account lifecycle. | `chart/values.yaml:566-568`<br>`chart/values.yaml:702-704`<br>`chart/values.yaml:993-995`<br>`chart/values.yaml:1064-1065`<br>`chart/values.yaml:1185-1187`<br>`chart/values.yaml:1237-1239` | STIG: no direct STIG rule<br>800-53: IA-2, IA-2(1), IA-2(12), IA-8, AC-2 | CAT II | Select the enterprise identity provider, register an OIDC or SAML client per package, and set sso.enabled: true for every exposed interface before accreditation. | Government decision |
| BB-IAM-002 | **Grafana ships with a hard-coded default administrator password** (Insecure by default). The Grafana authentication Secret rendered by the chart defaults to admin / prom-operator when the tenant does not override upstream.adminPassword, and the same default is duplicated into the Kiali integration Secret. Grafana is enabled by default and routed through the public gateway, so a default installation exposes an administrative login with a publicly documented password. | `chart/templates/grafana/flux/grafana-auth-secret.yaml:22-23`<br>`chart/templates/kiali/grafana-auth-secret.yaml:17-20`<br>`chart/values.yaml:1214-1216`<br>`docs/configuration/default-credentials.md:21` | STIG: no direct STIG rule<br>800-53: IA-5, IA-5(1), AC-2, CM-6 | CAT I | Set grafana.values.upstream.adminPassword (or admin.existingSecret) from a SOPS-encrypted value and enable SSO; consider a Kyverno rule that fails the Grafana HelmRelease when the default password is present. | Tenant |
| BB-IAM-003 | **NeuVector console defaults to admin / admin** (Insecure by default). NeuVector is enabled by default, exposed through the public gateway, and has SSO disabled. The documented initial credentials are admin / admin and the chart does not force a change. The console controls runtime enforcement policy for every node, so default credentials grant cluster-wide security control. | `chart/values.yaml:973-975`<br>`chart/values.yaml:993-995`<br>`docs/configuration/default-credentials.md:30` | STIG: no direct STIG rule<br>800-53: IA-5, IA-5(1), AC-2, AC-6 | CAT I | Enable NeuVector SSO with the enterprise identity provider and rotate or disable the local admin account during initial provisioning. | Tenant |
| BB-IAM-004 | **Prometheus and Alertmanager are exposed without authentication** (Insecure by default). Prometheus and Alertmanager have no built-in authentication. They are protected only when authservice is deployed and monitoring SSO is enabled; both are disabled by default. A default installation exposes metric queries (including label data about every workload) and alert silencing to any network path that reaches the gateway. | `docs/configuration/default-credentials.md:5-10`<br>`chart/values.yaml:1437-1442`<br>`chart/templates/monitoring/values.yaml:53` | STIG: V-242390 (analogous)<br>800-53: IA-2, AC-3, AC-14 | CAT II | Enable addons.authservice and monitoring.sso so both interfaces sit behind the identity-aware proxy, or remove their VirtualServices from the public gateway. | Government decision |
| BB-IAM-005 | **Default identity provider URL points to an external development realm** (Insecure by default). sso.url defaults to https://login.dso.mil/auth/realms/baby-yoda, the same value used by the development SSO example. A tenant who enables any package SSO without overriding the URL sends authentication flows across the enclave boundary to a realm the program does not administer. | `chart/values.yaml:93-94`<br>`docs/reference/configs/example/dev-sso-values.yaml:3` | STIG: no direct STIG rule<br>800-53: IA-8, IA-2, AC-20, SC-7 | CAT II | Set sso.url, sso.certificateAuthority, and per-package client identifiers to the program identity provider and constrain the sso egress definition to its CIDRs. | Government decision |
| BB-IAM-006 | **Grafana OAuth auto-provisions any identity provider user as Viewer** (Insecure by default). When Grafana SSO is enabled the chart sets allow_sign_up to true and role_attribute_path to the constant Viewer. Every authenticated identity provider user is auto-created in Grafana with read access to all dashboards and data sources regardless of group membership. | `chart/values.yaml:1250-1252`<br>`chart/templates/grafana/values.yaml:303-304`<br>`chart/templates/grafana/values.yaml:310-311` | STIG: no direct STIG rule<br>800-53: AC-2, AC-2(1), AC-3, AC-6(1) | CAT II | Set role_attribute_path to a JMESPath expression over identity provider groups, set role_attribute_strict, and restrict allow_sign_up or allowed_groups to the platform operator groups. | Tenant |
| BB-IAM-007 | **Bundled Keycloak uses development database and administrator credentials** (Documented tenant responsibility). Keycloak is disabled by default. When enabled without overrides it uses a bundled PostgreSQL with username and password `keycloak`, and the documented initial administrator credentials are admin / password. The production guidance states these are development credentials that must be replaced and that the bundled database is not production-suitable. | `chart/values.yaml:2044-2046`<br>`chart/templates/keycloak/values.yaml:86-94`<br>`docs/configuration/default-credentials.md:29`<br>`docs/configuration/production-considerations/keycloak.md:45-47` | STIG: no direct STIG rule<br>800-53: IA-5, IA-5(1), IA-5(7), SC-28 | CAT II | Provision an external database with SOPS-protected credentials, set addons.keycloak.database.*, and bootstrap the admin account from a Secret before exposing the realm. | Tenant |
| BB-IAM-008 | **Keycloak serves HTTP inside the cluster unless a certificate pair is supplied** (Documented tenant responsibility). Keycloak's internal scheme is HTTP and the management scheme is http unless addons.keycloak.ingress.cert and key are both provided, in which case the chart mounts them and switches to HTTPS with the passthrough gateway. CAC/PIV X.509 authentication requires the passthrough path, so the default configuration cannot support certificate-based login. | `chart/templates/keycloak/values.yaml:21`<br>`chart/templates/keycloak/values.yaml:107-108`<br>`chart/templates/keycloak/values.yaml:119-127`<br>`chart/values.yaml:2084-2090` | STIG: no direct STIG rule<br>800-53: SC-8, IA-2(12), IA-5(2) | CAT II | Supply a program PKI certificate pair, route Keycloak through the passthrough gateway, and configure the X.509 browser flow for CAC/PIV. | Tenant |
| BB-SEC-001 | **Credentials are accepted as plaintext Helm values and rendered into Secrets** (Documented tenant responsibility). Registry, Git, object storage, MinIO, Kiali OIDC, and Keycloak database credentials are all plaintext value fields. The chart base64-encodes them into Kubernetes Secrets; it cannot encrypt them at rest in Git. Protection depends on the tenant encrypting the values file with SOPS and on the cluster's Secret encryption, both documented as tenant responsibilities. | `chart/values.yaml:45-52`<br>`chart/values.yaml:78-87`<br>`chart/values.yaml:949-954`<br>`chart/values.yaml:1524-1528`<br>`chart/templates/git-credentials.yaml:25-35`<br>`chart/templates/kiali/sso-client-secret.yaml:9-10`<br>`docs/concepts/encryption.md:9-11` | STIG: no direct STIG rule<br>800-53: IA-5(7), SC-28, SC-28(1), SC-12 | CAT II | Store every credential-bearing values file as a SOPS-encrypted Secret with a KMS-backed key, enable etcd encryption at rest on the cluster, and audit Git history for any plaintext commit. | Tenant |
| BB-SEC-002 | **Mimir MinIO dependency ships hard-coded root and tenant credentials** (Secure by default; tenant can weaken). The optional Mimir MinIO object storage block defaults to root credentials minio / minio123 and tenant credentials mimir-user / supersecret. The block is disabled by default, but enabling it without overriding both credential pairs deploys object storage for metrics with publicly known passwords. | `chart/values.yaml:2355-2365` | STIG: no direct STIG rule<br>800-53: IA-5, IA-5(1), IA-5(7) | CAT II | Override configSecret and defaultUserCredentials from SOPS-encrypted values whenever minioObjectStorage is enabled; prefer external object storage for production. | Tenant |
| BB-SEC-003 | **Keycloak defaults embed a test-account password** (Insecure by default). The Keycloak package defaults contain a literal Cypress test password under bbtests. Because the block is part of the rendered package defaults, the value is written into the Keycloak values Secret on every deployment, including those with tests disabled. | `chart/templates/keycloak/values.yaml:73-78` | STIG: no direct STIG rule<br>800-53: IA-5(7), CM-7, SA-15(7) | CAT III | Move test credentials into a test-only values overlay that is applied solely when bbtests.enabled is true. | Platform |
| BB-SEC-004 | **Package credentials are passed through environment variables and chart values** (Insecure by default). When GitLab Redis integration is configured, Grafana receives GITLAB_REDIS_PASSWORD through an environment Secret and interpolates it in its data source configuration. NeuVector's metrics exporter receives its controller password as a chart value (CTRL_PASSWORD) rendered into the package values Secret. Both patterns place credentials where they are visible to anyone who can read pod specs or values Secrets. | `chart/templates/grafana/grafana-env-secret.yaml:13`<br>`chart/templates/grafana/values.yaml:222`<br>`chart/templates/neuvector/values.yaml:148-149` | STIG: V-242415 (analogous)<br>800-53: IA-5(7), SC-28, AC-6 | CAT III | Reference existing Secrets by name from the package charts (secretKeyRef or file mounts) instead of interpolating passwords into values and environment variables, and restrict RBAC read access to the *-values Secrets in the bigbang namespace. | Platform |
| BB-SEC-005 | **Flux drift detection ignores all Jobs, StatefulSets, and the Vault mutating webhook** (Insecure by default). Drift detection is enabled, but the defaults ignore every Job and StatefulSet, and the Vault package additionally ignores its MutatingWebhookConfiguration. Out-of-band modifications to stateful workloads (Loki, Keycloak database, Vault, MinIO) and to the Vault injector webhook are not detected or corrected by reconciliation. | `chart/values.yaml:146-154`<br>`chart/values.yaml:2127-2138` | STIG: no direct STIG rule<br>800-53: CM-3, CM-6, SI-7, SI-7(7) | CAT III | Narrow the StatefulSet ignore rule to the specific fields that cause false drift, and add an alert on StatefulSet and webhook changes from the Kubernetes audit log as a compensating control. | Platform |
| BB-AUD-001 | **Kubernetes API audit logs are not collected by the default logging pipeline** (Documented tenant responsibility). Alloy collects pod logs and cluster events, but no default pipeline ingests the API server audit log, and the chart does not configure an audit policy. The security model states that the control plane and a complete audit record remain platform-owner responsibilities. Without API audit ingestion, administrative actions against the cluster are not centrally recorded. | `chart/templates/alloy/values.yaml:299-301`<br>`chart/templates/alloy/values.yaml:342-344`<br>`docs/concepts/security-model.md:9`<br>`docs/concepts/security-model.md:23` | STIG: V-242461; V-242462; V-242463; V-242464; V-242465<br>800-53: AU-2, AU-3, AU-12, AU-6 | CAT II | Configure the API server audit policy and log path per the Kubernetes STIG, mount the audit log path into the Alloy DaemonSet (or ship it from the control plane), and route it to Loki or the enterprise SIEM. | Tenant |
| BB-AUD-002 | **Mesh access logging and tracing are coupled to the Tempo package** (Secure by default; tenant can weaken). Istio access log format, tracing, and default telemetry providers are rendered only when tempo.enabled is true. Tempo is enabled by default, so access logs are present, but disabling Tempo (a common cost or scope decision) silently removes gateway and sidecar access logging with no independent switch. | `chart/templates/istiod/values.yaml:69-82`<br>`chart/values.yaml:1043-1045` | STIG: no direct STIG rule<br>800-53: AU-2, AU-3, AU-12 | CAT II | Decouple accessLogFormat and the Prometheus metrics provider from the Tempo condition so access logging is always rendered, and gate only the tracing provider on Tempo. | Platform |
| BB-AUD-003 | **Default log store is a single-replica Loki on local filesystem storage with no retention or replication** (Insecure by default). Loki defaults to the monolith strategy. Without MinIO or external object storage the umbrella template selects filesystem chunk and index storage on a single SingleBinary replica and sets no retention period; the umbrella values do not touch the package chart's persistence settings, so chunks live on one persistent volume attached to that replica. The store therefore has no replicated or immutable copy: loss or corruption of that single volume, or deletion of the StatefulSet with its claim, removes the audit record, and there is no configured retention to satisfy AU-11. | `chart/values.yaml:934-936`<br>`chart/templates/loki/values.yaml:145-146`<br>`chart/templates/loki/values.yaml:157-168`<br>`chart/templates/loki/values.yaml:178-181` | STIG: no direct STIG rule<br>800-53: AU-4, AU-9, AU-9(2), AU-11 | CAT II | Configure loki.objectStorage against replicated object storage with bucket versioning or object lock, set a retention period matching the records schedule, and move to the scalable strategy for availability. | Government decision |
| BB-AUD-004 | **No external SIEM or log forwarding destination is configured** (Documented tenant responsibility). Alloy additionalDestinations is empty, so logs, metrics, and traces terminate in the in-cluster Loki, Prometheus, and Tempo instances. The security model states that Big Bang does not provide a SIEM, threat intelligence feed, or incident response program. Security-relevant events therefore never leave the cluster unless the tenant adds a destination. | `chart/values.yaml:892-893`<br>`docs/concepts/security-model.md:53` | STIG: no direct STIG rule<br>800-53: AU-6, AU-6(3), AU-12, SI-4 | CAT III | Add an Alloy destination for the enterprise SIEM (or a Loki remote) and define which log streams, alerts, and NeuVector events are forwarded. | Government decision |
| BB-SUP-001 | **Package charts are pulled from public Git sources by tag at reconciliation time** (Documented tenant responsibility). offline is false and every package source defaults to a repo1.dso.mil Git repository pinned by tag (or an OCI helm repository). Tags are mutable references and the sources are fetched over the Internet by Flux on each reconciliation. Mirroring into an internal registry or air-gapped source is documented as a tenant decision. | `chart/values.yaml:13-16`<br>`chart/values.yaml:1508-1515`<br>`docs/concepts/security-model.md:47-49` | STIG: no direct STIG rule<br>800-53: CM-14, SI-7, CM-2, SR-11 | CAT III | Mirror package charts and images into a program-controlled registry, switch sourceType to helmRepo against that registry, and set offline: true so no public GitRepository sources are created. | Government decision |
| BB-OPS-001 | **Velero backup is disabled by default and requires root node agents when enabled** (Documented tenant responsibility). Velero is disabled by default, so no platform state, Secrets, or persistent volumes are backed up. When enabled with the node agent, the agent is excluded from restrict-user-id and receives a Gatekeeper host filesystem exception because it must read the host pod directory as root. The security model lists backups and restore testing as platform-owner responsibilities. | `chart/values.yaml:2013-2015`<br>`chart/templates/kyverno-policies/values.yaml:942-954`<br>`chart/templates/gatekeeper/values.yaml:131-134`<br>`docs/concepts/security-model.md:76` | STIG: no direct STIG rule<br>800-53: CP-9, CP-10, AC-6 | CAT III | Decide the backup scope (cluster resources only versus persistent volumes), enable Velero against program object storage, and accept the node agent exception only if volume snapshots are not available. | Government decision |
<!-- END GENERATED: findings-table -->

## 4. Summary by control family

<!-- BEGIN GENERATED: family -->
| Family | Name | Findings | CAT I | CAT II | CAT III | Finding IDs |
| --- | --- | --- | --- | --- | --- | --- |
| AC | Access Control | 21 | 2 | 10 | 9 | BB-NET-003, BB-NET-004, BB-NET-006, BB-NET-009, BB-TLS-007, BB-TLS-008, BB-POL-001, BB-POL-004, BB-POL-005, BB-POL-006, BB-POL-007, BB-POL-010, BB-POL-011, BB-IAM-001, BB-IAM-002, BB-IAM-003, BB-IAM-004, BB-IAM-005, BB-IAM-006, BB-SEC-004, BB-OPS-001 |
| AU | Audit and Accountability | 5 | 0 | 3 | 2 | BB-POL-005, BB-AUD-001, BB-AUD-002, BB-AUD-003, BB-AUD-004 |
| CA | Assessment, Authorization, and Monitoring | 1 | 0 | 0 | 1 | BB-POL-012 |
| CM | Configuration Management | 20 | 1 | 7 | 12 | BB-NET-001, BB-NET-007, BB-TLS-007, BB-TLS-008, BB-POL-001, BB-POL-002, BB-POL-003, BB-POL-004, BB-POL-005, BB-POL-006, BB-POL-007, BB-POL-008, BB-POL-009, BB-POL-010, BB-POL-011, BB-POL-012, BB-IAM-002, BB-SEC-003, BB-SEC-005, BB-SUP-001 |
| CP | Contingency Planning | 1 | 0 | 0 | 1 | BB-OPS-001 |
| IA | Identification and Authentication | 15 | 2 | 10 | 3 | BB-TLS-002, BB-TLS-003, BB-TLS-004, BB-POL-001, BB-IAM-001, BB-IAM-002, BB-IAM-003, BB-IAM-004, BB-IAM-005, BB-IAM-007, BB-IAM-008, BB-SEC-001, BB-SEC-002, BB-SEC-003, BB-SEC-004 |
| RA | Risk Assessment | 1 | 0 | 0 | 1 | BB-POL-012 |
| SA | System and Services Acquisition | 1 | 0 | 0 | 1 | BB-SEC-003 |
| SC | System and Communications Protection | 23 | 0 | 12 | 11 | BB-NET-001, BB-NET-002, BB-NET-003, BB-NET-004, BB-NET-005, BB-NET-006, BB-NET-007, BB-NET-008, BB-NET-009, BB-TLS-001, BB-TLS-002, BB-TLS-003, BB-TLS-004, BB-TLS-005, BB-TLS-006, BB-TLS-008, BB-POL-007, BB-POL-011, BB-IAM-005, BB-IAM-007, BB-IAM-008, BB-SEC-001, BB-SEC-004 |
| SI | System and Information Integrity | 6 | 0 | 3 | 3 | BB-POL-002, BB-POL-004, BB-POL-008, BB-SEC-005, BB-AUD-004, BB-SUP-001 |
| SR | Supply Chain Risk Management | 2 | 0 | 1 | 1 | BB-POL-002, BB-SUP-001 |

A finding that cites controls from several families is counted once in each family, so the family totals exceed the 48 distinct findings.
<!-- END GENERATED: family -->

### 4.1 Zero Trust pillar coverage

<!-- BEGIN GENERATED: pillar -->
| Zero Trust pillar | Findings | Finding IDs |
| --- | --- | --- |
| Users | 10 | BB-NET-003, BB-IAM-001, BB-IAM-002, BB-IAM-003, BB-IAM-004, BB-IAM-005, BB-IAM-006, BB-IAM-007, BB-IAM-008, BB-SEC-003 |
| Devices | 3 | BB-TLS-002, BB-TLS-006, BB-IAM-008 |
| Network | 14 | BB-NET-001, BB-NET-002, BB-NET-003, BB-NET-004, BB-NET-005, BB-NET-006, BB-NET-007, BB-NET-008, BB-NET-009, BB-TLS-001, BB-TLS-002, BB-TLS-003, BB-TLS-005, BB-IAM-005 |
| Applications & Workloads | 18 | BB-NET-008, BB-NET-009, BB-TLS-003, BB-TLS-004, BB-TLS-007, BB-TLS-008, BB-POL-001, BB-POL-002, BB-POL-004, BB-POL-005, BB-POL-006, BB-POL-007, BB-POL-008, BB-POL-009, BB-POL-010, BB-POL-011, BB-IAM-001, BB-IAM-003 |
| Data | 8 | BB-NET-004, BB-IAM-006, BB-IAM-007, BB-SEC-001, BB-SEC-002, BB-SEC-004, BB-AUD-003, BB-OPS-001 |
| Visibility & Analytics | 10 | BB-TLS-004, BB-TLS-005, BB-POL-003, BB-POL-004, BB-POL-005, BB-IAM-004, BB-AUD-001, BB-AUD-002, BB-AUD-003, BB-AUD-004 |
| Automation & Orchestration | 5 | BB-POL-002, BB-POL-012, BB-SEC-001, BB-SEC-005, BB-SUP-001 |
<!-- END GENERATED: pillar -->

## 5. Summary by owner

<!-- BEGIN GENERATED: owner -->
| Owner | Findings | CAT I | CAT II | CAT III | Finding IDs |
| --- | --- | --- | --- | --- | --- |
| Platform | 17 | 0 | 3 | 14 | BB-NET-008, BB-NET-009, BB-TLS-001, BB-TLS-004, BB-TLS-005, BB-TLS-007, BB-POL-001, BB-POL-003, BB-POL-005, BB-POL-006, BB-POL-009, BB-POL-011, BB-POL-012, BB-SEC-003, BB-SEC-004, BB-SEC-005, BB-AUD-002 |
| Tenant | 20 | 2 | 14 | 4 | BB-NET-001, BB-NET-002, BB-NET-003, BB-NET-005, BB-NET-006, BB-NET-007, BB-TLS-002, BB-TLS-003, BB-TLS-006, BB-POL-007, BB-POL-008, BB-POL-010, BB-IAM-002, BB-IAM-003, BB-IAM-006, BB-IAM-007, BB-IAM-008, BB-SEC-001, BB-SEC-002, BB-AUD-001 |
| Government decision | 11 | 0 | 7 | 4 | BB-NET-004, BB-TLS-008, BB-POL-002, BB-POL-004, BB-IAM-001, BB-IAM-004, BB-IAM-005, BB-AUD-003, BB-AUD-004, BB-SUP-001, BB-OPS-001 |
| **Total** | **48** | | | | |
<!-- END GENERATED: owner -->

**Platform** items are engineering changes to this repository or to a package chart. **Tenant** items
are environment values, SOPS-protected Secrets, or cluster configuration that the deploying organization
must supply. **Government decision** items are listed in section 6.

## 6. Items requiring a Government decision

<!-- BEGIN GENERATED: government-decisions -->
11 findings require a Government risk-acceptance or architecture decision before an engineering change can be scheduled.

| ID | Decision required | Severity | Finding |
| --- | --- | --- | --- |
| BB-NET-004 | Cross-boundary egress: will platform telemetry and backup data leave the enclave to commercial or Government cloud object storage, and through which controlled path? | CAT II | Object storage egress allowed to any Internet address on TCP 443 |
| BB-TLS-008 | Architecture: sidecar or ambient data plane for the accredited baseline, given the different privileged-component exception sets each requires? | CAT III | Ambient data plane is opt-in and enlarges the pod security exception set when enabled |
| BB-POL-002 | Supply chain: which signing authority (Iron Bank cosign key, program key, or keyless identity) constitutes the trusted image provenance root for the baseline? | CAT II | Container image signature verification is disabled |
| BB-POL-004 | Risk acceptance: is a privileged, host-namespace runtime security agent (NeuVector, optionally Twistlock) accepted on every node in exchange for runtime detection coverage? | CAT II | Runtime security agents require privileged, host-namespace, and host-path-write exceptions selected by pod name glob |
| BB-IAM-001 | Identity: which enterprise identity provider (external realm, program-operated Keycloak, or other) is authoritative for platform administrative access, and is CAC/PIV-backed MFA mandatory for all exposed interfaces? | CAT II | Single sign-on is disabled for every enabled administrative interface |
| BB-IAM-004 | Exposure: are Prometheus and Alertmanager exposed at all outside the cluster, and if so is authservice with the enterprise identity provider the approved access path? | CAT II | Prometheus and Alertmanager are exposed without authentication |
| BB-IAM-005 | Identity boundary: is authentication permitted to traverse the enclave boundary to an externally operated realm, or must the identity provider reside inside the accreditation boundary? | CAT II | Default identity provider URL points to an external development realm |
| BB-AUD-003 | Audit retention: what retention period and storage class (replicated, immutable, off-cluster) are required for platform logs, and does the program provide the object storage to meet it? | CAT II | Default log store is a single-replica Loki on local filesystem storage with no retention or replication |
| BB-AUD-004 | Monitoring architecture: which enterprise SIEM or cybersecurity service provider receives platform security events, and over which approved egress path? | CAT III | No external SIEM or log forwarding destination is configured |
| BB-SUP-001 | Supply chain path: are chart and image sources permitted to be fetched from repo1.dso.mil and registry1.dso.mil over the Internet, or must all sources be mirrored inside the boundary? | CAT III | Package charts are pulled from public Git sources by tag at reconciliation time |
| BB-OPS-001 | Recovery: what platform state must be recoverable, to which storage, and is a root node agent on every node accepted to achieve file-level volume backup? | CAT III | Velero backup is disabled by default and requires root node agents when enabled |
<!-- END GENERATED: government-decisions -->

## 7. Evidence traceability

<!-- BEGIN GENERATED: traceability -->
All references are relative to the repository root at commit `6cfe27bd704eba732f795045ae5d0dd86e84e0ff`.

| ID | File | Line(s) | What the lines show | Commit |
| --- | --- | --- | --- | --- |
| BB-NET-001 | `chart/values.yaml` | 171-174 | Default 0.0.0.0/0 with instructions to derive the real endpoint CIDR | `6cfe27bd704e` |
| BB-NET-001 | `chart/templates/gatekeeper/values.yaml` | 70-76 | Only the metadata address is excluded when the default is used | `6cfe27bd704e` |
| BB-NET-002 | `chart/values.yaml` | 179-183 | Default 0.0.0.0/0 and private-endpoint guidance | `6cfe27bd704e` |
| BB-NET-002 | `chart/templates/gatekeeper/values.yaml` | 77-82 | vpcCidr appended as an additional ipBlock only when narrower than the control plane CIDR | `6cfe27bd704e` |
| BB-NET-003 | `chart/values.yaml` | 190-196 | sso egress definition with cidr 0.0.0.0/0 and no ports | `6cfe27bd704e` |
| BB-NET-004 | `chart/values.yaml` | 198-205 | storage-subnets definition | `6cfe27bd704e` |
| BB-NET-004 | `chart/values.yaml` | 179-182 | Private endpoint recommendation | `6cfe27bd704e` |
| BB-NET-005 | `chart/values.yaml` | 219-228 | kafka-subnets definition | `6cfe27bd704e` |
| BB-NET-006 | `chart/values.yaml` | 206-218 | redis-subnets | `6cfe27bd704e` |
| BB-NET-006 | `chart/values.yaml` | 229-239 | database-subnets | `6cfe27bd704e` |
| BB-NET-006 | `chart/values.yaml` | 244-262 | load-balancer-subnets and kubeAPI ingress | `6cfe27bd704e` |
| BB-NET-006 | `docs/configuration/production-considerations/keycloak.md` | 22 | Instruction to narrow private ranges | `6cfe27bd704e` |
| BB-NET-007 | `chart/values.yaml` | 168-170 | networkPolicies.enabled: true | `6cfe27bd704e` |
| BB-NET-007 | `docs/concepts/security-model.md` | 35 | Enforcement depends on a compatible CNI | `6cfe27bd704e` |
| BB-NET-007 | `docs/configuration/network-policies.md` | 7-9 | Policies supplement other controls | `6cfe27bd704e` |
| BB-NET-008 | `chart/templates/_helpers.tpl` | 1233-1237 | Wildcard egress from gateway NetworkPolicy | `6cfe27bd704e` |
| BB-NET-009 | `chart/templates/istiod/values.yaml` | 15 | hardened.enabled defaults to false | `6cfe27bd704e` |
| BB-NET-009 | `chart/templates/_helpers.tpl` | 1114-1124 | Sidecar and AuthorizationPolicy generation gated on hardened | `6cfe27bd704e` |
| BB-TLS-001 | `chart/templates/istio-gateway/_defaults.tpl` | 14-22 | HTTPS server with mode SIMPLE only | `6cfe27bd704e` |
| BB-TLS-001 | `docs/configuration/gateways.md` | 46-47 | Documented gateway TLS settings | `6cfe27bd704e` |
| BB-TLS-002 | `chart/values.yaml` | 2 | Default domain | `6cfe27bd704e` |
| BB-TLS-002 | `chart/ingress-certs.yaml` | 5-9 | Committed private key material for public-cert | `6cfe27bd704e` |
| BB-TLS-002 | `docs/reference/scripts/quickstart.sh` | 124 | Quickstart applies ingress-certs.yaml | `6cfe27bd704e` |
| BB-TLS-002 | `docs/getting-started/prerequisites.md` | 18 | Quickstart is evaluation only | `6cfe27bd704e` |
| BB-TLS-003 | `chart/templates/_helpers.tpl` | 1150-1154 | STRICT assumed as default mode | `6cfe27bd704e` |
| BB-TLS-003 | `docs/concepts/architecture.md` | 142-144 | Encryption varies for workloads outside the mesh | `6cfe27bd704e` |
| BB-TLS-004 | `chart/templates/monitoring/values.yaml` | 240-247 | ServiceMonitor TLS config | `6cfe27bd704e` |
| BB-TLS-004 | `chart/templates/monitoring/values.yaml` | 327-335 | Prometheus scrape TLS config | `6cfe27bd704e` |
| BB-TLS-004 | `chart/templates/grafana/values.yaml` | 99-106 | Grafana ServiceMonitor TLS config | `6cfe27bd704e` |
| BB-TLS-004 | `chart/templates/alloy/values.yaml` | 183-189 | Alloy remote-write TLS config | `6cfe27bd704e` |
| BB-TLS-005 | `chart/templates/alloy/values.yaml` | 39 | Loki push URL over http | `6cfe27bd704e` |
| BB-TLS-005 | `chart/templates/alloy/values.yaml` | 169-178 | Tempo OTLP destination with tls.insecure | `6cfe27bd704e` |
| BB-TLS-005 | `chart/templates/alloy/values.yaml` | 190-192 | Plain HTTP remote-write when no sidecar | `6cfe27bd704e` |
| BB-TLS-005 | `chart/templates/grafana/values.yaml` | 170 | Prometheus data source over http | `6cfe27bd704e` |
| BB-TLS-005 | `chart/templates/grafana/values.yaml` | 228 | Loki data source over http | `6cfe27bd704e` |
| BB-TLS-005 | `chart/templates/grafana/flux/provider.yaml` | 14 | Flux notification provider over http | `6cfe27bd704e` |
| BB-TLS-006 | `chart/values.yaml` | 1340-1342 | certManager enabled | `6cfe27bd704e` |
| BB-TLS-006 | `chart/values.yaml` | 1373-1377 | Both issuers disabled | `6cfe27bd704e` |
| BB-TLS-007 | `chart/values.yaml` | 274-276 | istioCNI.enabled: false | `6cfe27bd704e` |
| BB-TLS-007 | `chart/templates/kyverno-policies/values.yaml` | 438-441 | istio-init excluded from default security context | `6cfe27bd704e` |
| BB-TLS-008 | `chart/values.yaml` | 5-11 | istio.ambient.enabled: false | `6cfe27bd704e` |
| BB-TLS-008 | `chart/templates/kyverno-policies/values.yaml` | 13-58 | ztunnel policy exceptions | `6cfe27bd704e` |
| BB-TLS-008 | `chart/templates/gatekeeper/values.yaml` | 127-130 | ztunnel host filesystem exception | `6cfe27bd704e` |
| BB-POL-001 | `chart/templates/kyverno-policies/values.yaml` | 255-257 | Audit action | `6cfe27bd704e` |
| BB-POL-001 | `chart/templates/kyverno-policies/values.yaml` | 1022-1053 | Mutation limited to listed namespaces | `6cfe27bd704e` |
| BB-POL-002 | `chart/templates/kyverno-policies/values.yaml` | 405-407 | Signature policy disabled, Audit | `6cfe27bd704e` |
| BB-POL-002 | `docs/concepts/security-model.md` | 47-49 | Registry presence is not provenance | `6cfe27bd704e` |
| BB-POL-003 | `chart/templates/kyverno-policies/values.yaml` | 409-415 | Audit action and required label list | `6cfe27bd704e` |
| BB-POL-004 | `chart/templates/kyverno-policies/values.yaml` | 125-148 | Host namespace exceptions | `6cfe27bd704e` |
| BB-POL-004 | `chart/templates/kyverno-policies/values.yaml` | 242-251 | Privileged container exceptions | `6cfe27bd704e` |
| BB-POL-004 | `chart/templates/kyverno-policies/values.yaml` | 842-850 | Host path write exceptions | `6cfe27bd704e` |
| BB-POL-004 | `chart/templates/gatekeeper/values.yaml` | 115-122 | Gatekeeper host filesystem exceptions | `6cfe27bd704e` |
| BB-POL-005 | `chart/templates/kyverno-policies/values.yaml` | 752-770 | Host path mount exceptions | `6cfe27bd704e` |
| BB-POL-005 | `chart/templates/kyverno-policies/values.yaml` | 907-939 | SELinux spc_t exceptions | `6cfe27bd704e` |
| BB-POL-005 | `chart/templates/gatekeeper/values.yaml` | 123-126 | Alloy host filesystem exception | `6cfe27bd704e` |
| BB-POL-006 | `chart/templates/kyverno-policies/values.yaml` | 64-79 | add-default-capability-drop exclusions | `6cfe27bd704e` |
| BB-POL-006 | `chart/templates/kyverno-policies/values.yaml` | 351-402 | require-drop-all-capabilities exclusions | `6cfe27bd704e` |
| BB-POL-007 | `chart/values.yaml` | 1266-1268 | Twistlock disabled | `6cfe27bd704e` |
| BB-POL-007 | `chart/templates/kyverno-policies/values.yaml` | 683-693 | Unconfined AppArmor exception | `6cfe27bd704e` |
| BB-POL-007 | `chart/templates/kyverno-policies/values.yaml` | 129-139 | Host network exception and rationale | `6cfe27bd704e` |
| BB-POL-007 | `chart/templates/gatekeeper/values.yaml` | 137-145 | Gatekeeper exception | `6cfe27bd704e` |
| BB-POL-008 | `chart/templates/kyverno-policies/values.yaml` | 885-904 | Allow-list and gateway exclusion | `6cfe27bd704e` |
| BB-POL-008 | `chart/templates/gatekeeper/values.yaml` | 97-101 | Gatekeeper allow-list | `6cfe27bd704e` |
| BB-POL-009 | `chart/templates/kyverno-policies/values.yaml` | 193-209 | Gateway exclusion for auto tag | `6cfe27bd704e` |
| BB-POL-010 | `docs/getting-started/prerequisites.md` | 66-70 | Admission control is a tenant choice | `6cfe27bd704e` |
| BB-POL-010 | `docs/concepts/security-model.md` | 29-31 | Policy effectiveness depends on configuration | `6cfe27bd704e` |
| BB-POL-011 | `chart/values.yaml` | 2160-2162 | metricsServer enabled: auto | `6cfe27bd704e` |
| BB-POL-011 | `chart/values.yaml` | 2176-2184 | Automount true and kube-system namespace | `6cfe27bd704e` |
| BB-POL-012 | `chart/templates/kyverno-policies/values.yaml` | 234 | Privileged container exception | `6cfe27bd704e` |
| BB-POL-012 | `chart/templates/kyverno-policies/values.yaml` | 686 | AppArmor exception | `6cfe27bd704e` |
| BB-POL-012 | `chart/templates/kyverno-policies/values.yaml` | 697 | Capabilities exception | `6cfe27bd704e` |
| BB-POL-012 | `chart/templates/kyverno-policies/values.yaml` | 784 | Host path mount exception | `6cfe27bd704e` |
| BB-POL-012 | `chart/templates/kyverno-policies/values.yaml` | 847 | Host path write exception | `6cfe27bd704e` |
| BB-POL-012 | `chart/templates/kyverno-policies/values.yaml` | 915-921 | SELinux exceptions | `6cfe27bd704e` |
| BB-IAM-001 | `chart/values.yaml` | 566-568 | Kiali SSO disabled | `6cfe27bd704e` |
| BB-IAM-001 | `chart/values.yaml` | 702-704 | Kyverno Reporter SSO disabled | `6cfe27bd704e` |
| BB-IAM-001 | `chart/values.yaml` | 993-995 | NeuVector SSO disabled | `6cfe27bd704e` |
| BB-IAM-001 | `chart/values.yaml` | 1064-1065 | Tempo SSO disabled | `6cfe27bd704e` |
| BB-IAM-001 | `chart/values.yaml` | 1185-1187 | Monitoring SSO disabled | `6cfe27bd704e` |
| BB-IAM-001 | `chart/values.yaml` | 1237-1239 | Grafana SSO disabled | `6cfe27bd704e` |
| BB-IAM-002 | `chart/templates/grafana/flux/grafana-auth-secret.yaml` | 22-23 | Default admin credentials | `6cfe27bd704e` |
| BB-IAM-002 | `chart/templates/kiali/grafana-auth-secret.yaml` | 17-20 | Default duplicated for Kiali | `6cfe27bd704e` |
| BB-IAM-002 | `chart/values.yaml` | 1214-1216 | Grafana enabled | `6cfe27bd704e` |
| BB-IAM-002 | `docs/configuration/default-credentials.md` | 21 | Default credentials documented | `6cfe27bd704e` |
| BB-IAM-003 | `chart/values.yaml` | 973-975 | NeuVector enabled | `6cfe27bd704e` |
| BB-IAM-003 | `chart/values.yaml` | 993-995 | NeuVector SSO disabled | `6cfe27bd704e` |
| BB-IAM-003 | `docs/configuration/default-credentials.md` | 30 | Default admin / admin | `6cfe27bd704e` |
| BB-IAM-004 | `docs/configuration/default-credentials.md` | 5-10 | No built-in authentication | `6cfe27bd704e` |
| BB-IAM-004 | `chart/values.yaml` | 1437-1442 | authservice disabled | `6cfe27bd704e` |
| BB-IAM-004 | `chart/templates/monitoring/values.yaml` | 53 | authservice gating expression | `6cfe27bd704e` |
| BB-IAM-005 | `chart/values.yaml` | 93-94 | Default sso.url | `6cfe27bd704e` |
| BB-IAM-005 | `docs/reference/configs/example/dev-sso-values.yaml` | 3 | Same realm in the development example | `6cfe27bd704e` |
| BB-IAM-006 | `chart/values.yaml` | 1250-1252 | allow_sign_up true, role Viewer | `6cfe27bd704e` |
| BB-IAM-006 | `chart/templates/grafana/values.yaml` | 303-304 | Rendered from monitoring.sso | `6cfe27bd704e` |
| BB-IAM-006 | `chart/templates/grafana/values.yaml` | 310-311 | Rendered from grafana.sso | `6cfe27bd704e` |
| BB-IAM-007 | `chart/values.yaml` | 2044-2046 | Keycloak disabled | `6cfe27bd704e` |
| BB-IAM-007 | `chart/templates/keycloak/values.yaml` | 86-94 | Default database credentials | `6cfe27bd704e` |
| BB-IAM-007 | `docs/configuration/default-credentials.md` | 29 | admin / password | `6cfe27bd704e` |
| BB-IAM-007 | `docs/configuration/production-considerations/keycloak.md` | 45-47 | Development credentials must be replaced | `6cfe27bd704e` |
| BB-IAM-008 | `chart/templates/keycloak/values.yaml` | 21 | TLS enabled only with cert and key | `6cfe27bd704e` |
| BB-IAM-008 | `chart/templates/keycloak/values.yaml` | 107-108 | internalScheme HTTP | `6cfe27bd704e` |
| BB-IAM-008 | `chart/templates/keycloak/values.yaml` | 119-127 | HTTPS only when TLS enabled | `6cfe27bd704e` |
| BB-IAM-008 | `chart/values.yaml` | 2084-2090 | Passthrough gateway requirement | `6cfe27bd704e` |
| BB-SEC-001 | `chart/values.yaml` | 45-52 | registryCredentials | `6cfe27bd704e` |
| BB-SEC-001 | `chart/values.yaml` | 78-87 | git.credentials | `6cfe27bd704e` |
| BB-SEC-001 | `chart/values.yaml` | 949-954 | Loki object storage keys | `6cfe27bd704e` |
| BB-SEC-001 | `chart/values.yaml` | 1524-1528 | MinIO keys | `6cfe27bd704e` |
| BB-SEC-001 | `chart/templates/git-credentials.yaml` | 25-35 | Rendered into Secret data | `6cfe27bd704e` |
| BB-SEC-001 | `chart/templates/kiali/sso-client-secret.yaml` | 9-10 | OIDC secret in stringData | `6cfe27bd704e` |
| BB-SEC-001 | `docs/concepts/encryption.md` | 9-11 | SOPS requirement | `6cfe27bd704e` |
| BB-SEC-002 | `chart/values.yaml` | 2355-2365 | Hard-coded MinIO credentials | `6cfe27bd704e` |
| BB-SEC-003 | `chart/templates/keycloak/values.yaml` | 73-78 | Literal test password in defaults | `6cfe27bd704e` |
| BB-SEC-004 | `chart/templates/grafana/grafana-env-secret.yaml` | 13 | Redis password in env Secret | `6cfe27bd704e` |
| BB-SEC-004 | `chart/templates/grafana/values.yaml` | 222 | Env var interpolated into data source | `6cfe27bd704e` |
| BB-SEC-004 | `chart/templates/neuvector/values.yaml` | 148-149 | Exporter password as chart value | `6cfe27bd704e` |
| BB-SEC-005 | `chart/values.yaml` | 146-154 | Job and StatefulSet ignored | `6cfe27bd704e` |
| BB-SEC-005 | `chart/values.yaml` | 2127-2138 | Vault webhook ignored | `6cfe27bd704e` |
| BB-AUD-001 | `chart/templates/alloy/values.yaml` | 299-301 | Pod log collection | `6cfe27bd704e` |
| BB-AUD-001 | `chart/templates/alloy/values.yaml` | 342-344 | Cluster event collection | `6cfe27bd704e` |
| BB-AUD-001 | `docs/concepts/security-model.md` | 9 | Control plane is platform-owner responsibility | `6cfe27bd704e` |
| BB-AUD-001 | `docs/concepts/security-model.md` | 23 | Flux history is not an audit system | `6cfe27bd704e` |
| BB-AUD-002 | `chart/templates/istiod/values.yaml` | 69-82 | Access logging gated on tempo.enabled | `6cfe27bd704e` |
| BB-AUD-002 | `chart/values.yaml` | 1043-1045 | Tempo enabled | `6cfe27bd704e` |
| BB-AUD-003 | `chart/values.yaml` | 934-936 | monolith strategy | `6cfe27bd704e` |
| BB-AUD-003 | `chart/templates/loki/values.yaml` | 145-146 | filesystem storage type | `6cfe27bd704e` |
| BB-AUD-003 | `chart/templates/loki/values.yaml` | 157-168 | boltdb-shipper and filesystem chunk directory | `6cfe27bd704e` |
| BB-AUD-003 | `chart/templates/loki/values.yaml` | 178-181 | SingleBinary with one replica | `6cfe27bd704e` |
| BB-AUD-004 | `chart/values.yaml` | 892-893 | additionalDestinations empty | `6cfe27bd704e` |
| BB-AUD-004 | `docs/concepts/security-model.md` | 53 | No SIEM or incident response program provided | `6cfe27bd704e` |
| BB-SUP-001 | `chart/values.yaml` | 13-16 | offline: false | `6cfe27bd704e` |
| BB-SUP-001 | `chart/values.yaml` | 1508-1515 | Example package source pinned by tag | `6cfe27bd704e` |
| BB-SUP-001 | `docs/concepts/security-model.md` | 47-49 | Registry presence is not provenance | `6cfe27bd704e` |
| BB-OPS-001 | `chart/values.yaml` | 2013-2015 | Velero disabled | `6cfe27bd704e` |
| BB-OPS-001 | `chart/templates/kyverno-policies/values.yaml` | 942-954 | Node agent root exception | `6cfe27bd704e` |
| BB-OPS-001 | `chart/templates/gatekeeper/values.yaml` | 131-134 | Node agent host filesystem exception | `6cfe27bd704e` |
| BB-OPS-001 | `docs/concepts/security-model.md` | 76 | Backups are an owner responsibility | `6cfe27bd704e` |
<!-- END GENERATED: traceability -->

## 8. Maintaining this assessment

- Edit findings only in `cloud-security-findings.json`, then run
  `python3 docs/assessments/build_assessment_summary.py` from the repository root to regenerate every
  table and count in this file.
- Run `python3 -m pytest docs/assessments/test_assessment.py` to confirm that the Markdown and JSON agree
  in both directions, that every `file:line` reference exists at the current commit, and that the
  generated sections are current.
- When the assessed commit changes, update `metadata.commit` in the JSON and re-run both commands; the
  test will report any evidence line that has moved.
