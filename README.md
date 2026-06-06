# AltSign-Linux (dragoshont fork)

Fork of [NyaMisty/AltSign-Linux](https://github.com/NyaMisty/AltSign-Linux) — the
signing library embedded as a submodule inside
[AltServer-Linux](https://github.com/dragoshont/AltServer-Linux).

## Why this fork exists

Upstream AltSign-Linux signs through a 4-year-old vendored `ldid` that emits a
dual SHA1+SHA256 CodeDirectory and legacy-DER entitlements. Modern AMFI (iOS
17+/26, Apple Silicon) rejects those signatures — apps install but are **killed
at launch (`Code=85`)**.

This fork is part of **[altserver-stack](https://github.com/dragoshont/altserver-stack)**,
which rewrites `Signer::SignApp` to delegate the codesign step to a patched
[zsign](https://github.com/dragoshont/zsign) (upstream PR
[zhlynn/zsign#391](https://github.com/zhlynn/zsign/pull/391) — SHA256-only
CodeDirectory + Apple-canonical DER entitlements). Pinned at `0daf107`, verified
end-to-end on a physical **iPhone 16 Pro Max running iOS 26.5**.

It also serves as a stable, self-owned submodule target so the AltServer-Linux
build path never resolves to a deletable upstream account.

## Just want the result?

Don't build this — pull the prebuilt, fully-static, iOS-26-valid binaries:

```bash
docker run --rm -v /opt/altserver:/dest \
  ghcr.io/dragoshont/altserver-linux:latest-main extract
```

Full build chain and the whole story:
**https://github.com/dragoshont/altserver-stack**
