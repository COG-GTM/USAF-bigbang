{{- /*
GitLab CNG image tags that Big Bang pins ahead of the GitLab package chart.

CVE-2026-110264 (CVSS 10.0, unauthenticated remote code execution through an integer overflow in
the Onigmo regular expression compiler) is fixed in GitLab 19.3.6, 19.4.3 and 19.5.1. Every
published Big Bang GitLab package tag up to and including 10.4.2-bb.1 ships GitLab 19.4.2 or
older, so while the configured package tag is below 10.5.1-bb.0 the umbrella overrides every CNG
image tag the package sets (chart/values.yaml in the package) to the patched Verified Publisher
release that is mirrored in registry1. Operator overlays under addons.gitlab.values still win.

Remove this override, and its unit tests, once the default package pin is at or above 10.5.1-bb.0.
*/ -}}
{{- define "bigbang.gitlab.patchedImageTags" -}}
{{- $gitlab := .Values.addons.gitlab -}}
{{- $packageTag := ternary (dig "helmRepo" "tag" "" $gitlab) (dig "git" "tag" "" $gitlab) (eq $gitlab.sourceType "helmRepo") | toString -}}
{{- $patchedPackageConstraint := "< 10.5.1-0" -}}
{{- $patchedImageTag := "v19.5.1-ubi" -}}
{{- if and (regexMatch "^[0-9]+\\.[0-9]+\\.[0-9]+" $packageTag) (semverCompare $patchedPackageConstraint $packageTag) }}
global:
  certificates:
    image:
      tag: {{ $patchedImageTag }}
  kubectl:
    image:
      tag: {{ $patchedImageTag }}
  gitlabBase:
    image:
      tag: {{ $patchedImageTag }}
upstream:
  shared-secrets:
    selfsign:
      image:
        tag: {{ $patchedImageTag }}
  gitlab:
    toolbox:
      image:
        tag: {{ $patchedImageTag }}
    migrations:
      image:
        tag: {{ $patchedImageTag }}
    webservice:
      image:
        tag: {{ $patchedImageTag }}
      workhorse:
        tag: {{ $patchedImageTag }}
    sidekiq:
      image:
        tag: {{ $patchedImageTag }}
    gitaly:
      image:
        tag: {{ $patchedImageTag }}
      cgroups:
        initContainer:
          image:
            tag: {{ $patchedImageTag }}
    geo-logcursor:
      image:
        tag: {{ $patchedImageTag }}
    mailroom:
      image:
        tag: {{ $patchedImageTag }}
    gitlab-pages:
      image:
        tag: {{ $patchedImageTag }}
    kas:
      image:
        tag: {{ $patchedImageTag }}
    praefect:
      image:
        tag: {{ $patchedImageTag }}
{{- end }}
{{- end }}
