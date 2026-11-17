#!/bin/bash
# Assemble the Debian package from an already-built proxy binary.
#
# Plain dpkg-deb rather than debhelper: the package is one binary, one
# conffile and one unit, and the maintainer scripts must NOT do what
# dh_installsystemd does by default (enable and start the unit). Runtime
# dependencies come from dpkg-shlibdeps against the binary itself, so they
# match whatever libcurl/libssl it was linked against on this release.
#
# Usage: build_deb.sh BINARY VERSION OUTDIR
#   -> OUTDIR/dns-encrypted-proxy_<VERSION>_<arch>.deb
set -euo pipefail

bin="${1:?usage: $0 BINARY VERSION OUTDIR}"
version="${2:?usage: $0 BINARY VERSION OUTDIR}"
outdir="${3:?usage: $0 BINARY VERSION OUTDIR}"

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pkg=dns-encrypted-proxy
arch="$(dpkg --print-architecture)"

if [[ ! "$version" =~ ^[0-9][0-9A-Za-z.+~-]*$ ]]; then
    echo "build_deb: '$version' is not a valid Debian version" >&2
    exit 1
fi
if [ ! -x "$bin" ]; then
    echo "build_deb: binary not found or not executable: $bin" >&2
    exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
root="$work/root"

install -D -m 0755 "$bin" "$root/usr/sbin/$pkg"
install -D -m 0644 "$repo/dns-encrypted-proxy.conf.example" "$root/etc/$pkg/$pkg.conf"
install -D -m 0644 "$repo/packaging/$pkg.service" "$root/usr/lib/systemd/system/$pkg.service"
install -D -m 0644 "$repo/README.md" "$root/usr/share/doc/$pkg/README.md"
install -D -m 0644 "$repo/Manual.md" "$root/usr/share/doc/$pkg/Manual.md"
cat > "$root/usr/share/doc/$pkg/copyright" <<COPYRIGHT
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: $pkg
Source: https://git.airies.net/vifair22/dns-encrypted-proxy

Files: *
License: GPL-3
 On Debian systems the full text is in /usr/share/common-licenses/GPL-3.
COPYRIGHT

# dpkg-shlibdeps insists on a debian/control in its working directory; a
# stub is enough for it to map the binary's NEEDED entries to packages.
mkdir -p "$work/shlibs/debian"
printf 'Source: %s\n\nPackage: %s\nArchitecture: any\n' "$pkg" "$pkg" > "$work/shlibs/debian/control"
depends="$(cd "$work/shlibs" && dpkg-shlibdeps -O -e"$root/usr/sbin/$pkg" 2>/dev/null \
    | sed -n 's/^shlibs:Depends=//p')"
if [ -z "$depends" ]; then
    echo "build_deb: dpkg-shlibdeps produced no dependencies" >&2
    exit 1
fi

# procps provides the /bin/kill that the unit's ExecReload runs; minimal
# images (containers, debootstrap --variant=minbase) do not carry it.
depends="$depends, procps"

installed_kb="$(du -sk "$root" | cut -f1)"
mkdir -p "$root/DEBIAN"
cat > "$root/DEBIAN/control" <<CONTROL
Package: $pkg
Version: $version
Architecture: $arch
Maintainer: dns-encrypted-proxy maintainers <noreply@git.airies.net>
Installed-Size: $installed_kb
Depends: $depends
Section: net
Priority: optional
Homepage: https://git.airies.net/vifair22/dns-encrypted-proxy
Description: classic DNS front end for DoH/DoT upstreams
 Serves plain DNS over UDP and TCP and forwards over DNS-over-HTTPS or
 DNS-over-TLS, with a shared cache, health-aware upstream dispatch,
 Prometheus metrics, systemd Type=notify readiness, and SIGHUP to redial
 upstream connections after a route change.
 .
 The systemd unit is installed disabled; enable it explicitly.
CONTROL
echo "/etc/$pkg/$pkg.conf" > "$root/DEBIAN/conffiles"
install -m 0755 "$repo/packaging/debian/postinst" "$root/DEBIAN/postinst"
install -m 0755 "$repo/packaging/debian/prerm" "$root/DEBIAN/prerm"
install -m 0755 "$repo/packaging/debian/postrm" "$root/DEBIAN/postrm"

mkdir -p "$outdir"
out="$outdir/${pkg}_${version}_${arch}.deb"
dpkg-deb --root-owner-group -Zxz --build "$root" "$out" >/dev/null
echo "build_deb: $out"
echo "build_deb: Depends: $depends"
