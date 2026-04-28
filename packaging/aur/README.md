# AUR Package for sigil-device

This directory contains the PKGBUILD and metadata for publishing `sigil-device` to the Arch User Repository (AUR).

## Files

- `sigil-device/PKGBUILD` — Pacman build script (builds from source)
- `sigil-device/.SRCINFO` — AUR metadata (generated from PKGBUILD)

## Publishing to AUR (One-Time Setup)

### 1. Create AUR account

- Go to https://aur.archlinux.org/register
- Create account with SSH public key

### 2. Clone AUR repository

```bash
git clone ssh://aur@aur.archlinux.org/sigil-device.git aur-sigil-device
cd aur-sigil-device
```

### 3. Copy PKGBUILD and .SRCINFO

```bash
cp ../cli-device/packaging/aur/sigil-device/PKGBUILD .
cp ../cli-device/packaging/aur/sigil-device/.SRCINFO .
```

### 4. Update checksums

After the first GitHub release (v0.1.0), download the tarball and compute the SHA256:

```bash
curl -LO https://github.com/sigilauth/cli-device/archive/v0.1.0.tar.gz
sha256sum v0.1.0.tar.gz
```

Update `sha256sums` in PKGBUILD with the actual checksum (replace `SKIP`).

Regenerate .SRCINFO:

```bash
makepkg --printsrcinfo > .SRCINFO
```

### 5. Commit and push

```bash
git add PKGBUILD .SRCINFO
git commit -m "Initial release: v0.1.0"
git push
```

The package is now live at https://aur.archlinux.org/packages/sigil-device

## Updating for New Releases

For each new release (e.g., v0.2.0):

1. Update `pkgver` in PKGBUILD
2. Update `pkgrel` to 1 (reset on version bump)
3. Download new tarball and update `sha256sums`
4. Regenerate .SRCINFO: `makepkg --printsrcinfo > .SRCINFO`
5. Test build: `makepkg -si`
6. Commit and push to AUR

```bash
cd aur-sigil-device
# Edit PKGBUILD (update pkgver, pkgrel, sha256sums)
makepkg --printsrcinfo > .SRCINFO
makepkg -si  # Test build and install
git add PKGBUILD .SRCINFO
git commit -m "Update to v0.2.0"
git push
```

## User Installation

Once published, Arch users install via AUR helper:

```bash
# Using yay
yay -S sigil-device

# Using paru
paru -S sigil-device

# Manual build
git clone https://aur.archlinux.org/sigil-device.git
cd sigil-device
makepkg -si
```

## Binary Package Variant

For a binary package (pre-built, faster install), create a separate `sigil-device-bin` PKGBUILD that downloads the release binary instead of building from source. This is optional but recommended for users who don't want to compile Go code.

## References

- [AUR Submission Guidelines](https://wiki.archlinux.org/title/AUR_submission_guidelines)
- [PKGBUILD Documentation](https://wiki.archlinux.org/title/PKGBUILD)
- [makepkg Manual](https://man.archlinux.org/man/makepkg.8)
