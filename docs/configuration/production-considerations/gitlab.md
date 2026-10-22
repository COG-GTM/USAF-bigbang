# GitLab Production Considerations

[[_TOC_]]

The current Big Bang GitLab package uses GitLab 19 and Helm chart 10.

> [!IMPORTANT]
> GitLab 19 no longer includes bundled PostgreSQL, Redis, or MinIO charts. Big Bang does not provision replacements as part of the GitLab package. Provision PostgreSQL, Redis or Valkey, and object storage independently before enabling a new GitLab deployment or upgrading an existing deployment.

There is no automatic migration from the formerly bundled services. Existing deployments must migrate while still running the latest GitLab 18.11 and chart 9.11 patch. Follow the package's [GitLab 19 upgrade notes](https://repo1.dso.mil/big-bang/product/packages/gitlab/-/blob/main/docs/gitlab-19-upgrade.md) before upgrading.

## Patch Level for CVE-2026-110264

CVE-2026-110264 (CVSS 10.0) lets an unauthenticated user execute arbitrary code on GitLab 19.3 before 19.3.6, 19.4 before 19.4.3, and 19.5 before 19.5.1 through an integer overflow when GitLab compiles a specially crafted regular expression. Big Bang publishes `gitlab.<domain>` on the public ingress gateway, so every deployment with `addons.gitlab.enabled: true` is reachable by the attacker this advisory describes.

Every published Big Bang GitLab package tag up to and including `10.4.2-bb.1` ships GitLab 19.4.2 or older. Until a package tag at or above `10.5.1-bb.0` exists, Big Bang pins the GitLab package to `10.4.2-bb.1` and overrides every CNG image tag the package sets (`global.certificates`, `global.kubectl`, `global.gitlabBase`, `upstream.shared-secrets.selfsign`, and each `upstream.gitlab.<component>` image, including Workhorse and the Gitaly cgroups init container) to `v19.5.1-ubi`, the patched Verified Publisher release mirrored in registry1. The override applies only while the configured `addons.gitlab.git.tag` or `addons.gitlab.helmRepo.tag` is a semantic version below `10.5.1-0`; a branch, commit, or semver-range source is left untouched because Big Bang cannot tell which GitLab version it ships.

> [!WARNING]
> Chart `10.4.x` with GitLab `19.5.1` images is a cross-minor combination that upstream GitLab documents as an override, not a tested release pairing. Review the [GitLab 19.5 upgrade notes](https://docs.gitlab.com/update/versions/gitlab_19_changes/) before Flux reconciles the change, and take a backup first. To stay on the exact chart pairing instead, set the image tags beneath `addons.gitlab.values` to a release you have validated and restrict `routes.inbound.gitlab` to trusted networks until the package publishes a patched tag.

When the GitLab package publishes `10.5.1-bb.0` or later, move `addons.gitlab.git.tag` and `addons.gitlab.helmRepo.tag` to that tag. The override disables itself for that pin; remove `chart/templates/gitlab/_image-overrides.tpl` and its unit tests in the following release.

## Configure Required External Services

GitLab 19 requires:

- PostgreSQL 17.x with the [extensions required by GitLab](https://docs.gitlab.com/install/requirements/#postgresql).
- Redis 7.0 or later, or Valkey 7.2 or later. Redis Cluster and serverless offerings are not supported. Redis 7.2 is recommended by the package documentation.
- GitLab-supported object storage with separate buckets for each enabled object type, Registry, and backup temporary storage.

Big Bang provides convenience values for the primary PostgreSQL connection, Redis authentication, and S3-compatible object storage. The Redis endpoint is an upstream GitLab value and must be supplied through `addons.gitlab.values.global.redis`.

```yaml
addons:
  gitlab:
    enabled: true

    database:
      host: postgresql.example.svc.cluster.local
      port: 5432
      database: gitlabhq_production
      username: gitlab
      password: "<encrypted-or-injected-password>"

    redis:
      password: "<encrypted-or-injected-password>"

    values:
      global:
        redis:
          host: redis.example.svc.cluster.local
          port: 6379

    objectStorage:
      type: s3
      endpoint: https://s3.us-gov-west-1.amazonaws.com
      region: us-gov-west-1
      accessKey: "<encrypted-or-injected-access-key>"
      accessSecret: "<encrypted-or-injected-secret-key>"
      bucketPrefix: production
      iamProfile: ""
```

Supplying `addons.gitlab.database.host` makes Big Bang configure `global.psql` and create the database password Secret. Supplying `addons.gitlab.redis.password` creates `gitlab-redis-secret-bb`; it does not configure the Redis host. Protect all credentials with SOPS or another secret-management workflow.

For object storage:

- Include `http://` or `https://` in `endpoint`. GitLab 19 requires a full URI for non-AWS S3-compatible endpoints.
- Set `regionendpoint` when Registry must use a different endpoint from the Rails applications.
- Use either `iamProfile` or `accessKey` and `accessSecret`, not both.
- Provision every bucket reported by the Big Bang Helm notes. With `bucketPrefix: production`, Big Bang configures names such as `production-gitlab-registry`, `production-gitlab-lfs`, `production-gitlab-artifacts`, `production-gitlab-backup`, and `production-gitlab-backup-tmp`; it does not create the buckets.

Advanced deployments can configure the upstream `global.psql`, `global.redis`, consolidated object store, Registry storage, and Toolbox backup settings directly beneath `addons.gitlab.values`. See the package's [operational production settings](https://repo1.dso.mil/big-bang/product/packages/gitlab/-/blob/main/docs/operational-production-settings.md).

## Tune Flux Reconciliation

Large GitLab installations commonly need a longer HelmRelease timeout. Tune retries for the environment, and use `addons.gitlab.dependsOn` when an operator must be Ready before GitLab creates or connects to its resources.

```yaml
addons:
  gitlab:
    flux:
      timeout: 30m
      upgrade:
        remediation:
          retries: 8
```

## Size GitLab from Measured Load

The package defaults target development, demonstrations, and CI. Size Webservice, Sidekiq, Gitaly, Registry, PostgreSQL, Redis or Valkey, and object storage from measured workload and availability requirements. Upstream GitLab subchart values belong below `addons.gitlab.values.upstream`; for example:

```yaml
addons:
  gitlab:
    values:
      upstream:
        gitlab:
          webservice:
            resources: {}
          sidekiq:
            resources: {}
          gitaly:
            resources: {}
```

The package's [Kubernetes resource configuration](https://repo1.dso.mil/big-bang/product/packages/gitlab/-/blob/main/docs/k8s-resources.md) lists the supported paths. Its numbers are examples, not production recommendations.

## Protect the Rails Secret

GitLab uses its Rails Secret to encrypt protected database fields. If the Secret changes, GitLab can no longer decrypt that data and logs may contain `OpenSSL::Cipher::CipherError`.

For a new deployment, define stable Rails secret data through Big Bang:

```yaml
addons:
  gitlab:
    railsSecret: |
      production:
        secret_key_base: <secret>
        otp_key_base: <secret>
        db_key_base: <secret>
```

Big Bang creates `gitlab-rails-secret-bb` and configures GitLab to use it. Store this value in a SOPS-encrypted file or an equivalent protected system.

Alternatively, create and manage the Secret independently and select it with:

```yaml
addons:
  gitlab:
    values:
      global:
        railsSecrets:
          secret: my-gitlab-rails-secret
```

Back up the Rails Secret separately from the cluster and include it in disaster-recovery tests. Existing deployments must preserve their current Rails Secret across upgrades; generating new values is not a migration strategy.
