# AUR Package for devssl

This directory contains the PKGBUILD and .SRCINFO files for the Arch User Repository (AUR).

## Publishing to AUR

1. Create an AUR account at <https://aur.archlinux.org/>
2. Add your SSH key to your AUR account
3. Clone the AUR package (first time):

   ```bash
   git clone ssh://aur@aur.archlinux.org/devssl.git aur-repo
   ```

4. Copy the PKGBUILD and .SRCINFO to the cloned repo
5. Commit and push

## Updating the Package

When releasing a new version:

1. Update `pkgver` in PKGBUILD
2. Update the sha256sum (or use 'SKIP' during development)
3. Regenerate .SRCINFO:

   ```bash
   makepkg --printsrcinfo > .SRCINFO
   ```

4. Commit and push to AUR

## Testing Locally

```bash
# Test the PKGBUILD
makepkg -si

# Or just build without installing
makepkg -s
```

## Generating sha256sum

After tagging a release on GitHub, download the tarball and generate the checksum:

```bash
curl -sL https://github.com/jayashankarvr/devssl/archive/v0.1.0.tar.gz | sha256sum
```

Then update the `sha256sums` array in PKGBUILD.
