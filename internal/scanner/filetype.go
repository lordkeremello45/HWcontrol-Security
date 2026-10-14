package scanner

import (
	"bytes"
	"path/filepath"
	"strings"
)

// IdentifyFileType reports a format based on file signatures first and the filename
// extension only as a fallback. The result is a classification hint, not a safety verdict.
func IdentifyFileType(path string, header []byte) string {
	if t := identifyMagic(header); t != "" {
		return t
	}
	name := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(name))
	if strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tgz") {
		return "archive:tar-gzip"
	}
	if strings.HasSuffix(name, ".tar.xz") {
		return "archive:tar-xz"
	}
	if strings.HasSuffix(name, ".tar.zst") {
		return "archive:tar-zstd"
	}
	if strings.HasSuffix(name, ".tar") {
		return "archive:tar"
	}
	if strings.HasSuffix(name, ".msixbundle") || strings.HasSuffix(name, ".appxbundle") {
		return "package:windows-bundle"
	}
	if strings.HasSuffix(name, ".flatpakref") {
		return "package:flatpak-reference"
	}
	if strings.HasSuffix(name, ".appimage") {
		return "package:appimage"
	}
	if strings.HasSuffix(name, ".wasm") {
		return "executable:wasm"
	}
	if strings.HasSuffix(name, ".jar") {
		return "archive:java-jar"
	}
	if strings.HasSuffix(name, ".app") {
		return "package:macos-app"
	}
	if strings.HasSuffix(name, ".kext") {
		return "package:macos-kext"
	}
	if strings.HasSuffix(name, ".flatpak") {
		return "package:flatpak"
	}
	if strings.HasSuffix(name, ".deb") {
		return "package:debian"
	}
	if strings.HasSuffix(name, ".rpm") {
		return "package:rpm"
	}
	if strings.HasSuffix(name, ".snap") {
		return "package:snap"
	}
	if strings.HasSuffix(name, ".msix") || strings.HasSuffix(name, ".appx") {
		return "package:windows-appx"
	}
	if strings.HasSuffix(name, ".msi") {
		return "package:windows-msi"
	}
	if strings.HasSuffix(name, ".msu") || strings.HasSuffix(name, ".cab") {
		return "package:windows-cabinet"
	}
	if strings.HasSuffix(name, ".pkg") || strings.HasSuffix(name, ".mpkg") {
		return "package:macos-installer"
	}
	if strings.HasSuffix(name, ".dmg") {
		return "package:macos-disk-image"
	}
	if strings.HasSuffix(name, ".xip") {
		return "archive:apple-xip"
	}
	if strings.HasSuffix(name, ".dll") || strings.HasSuffix(name, ".sys") || strings.HasSuffix(name, ".exe") {
		return "executable:windows-pe"
	}
	if strings.HasSuffix(name, ".dylib") || strings.HasSuffix(name, ".so") {
		return "executable:native-library"
	}
	if strings.HasSuffix(name, ".kext") {
		return "package:macos-kext"
	}
	if strings.HasSuffix(name, ".o") {
		return "object:native"
	}
	if strings.HasSuffix(name, ".bin") {
		return "generic:binary"
	}
	if strings.HasSuffix(name, ".zip") {
		return "archive:zip"
	}
	if strings.HasSuffix(name, ".7z") {
		return "archive:7zip"
	}
	if strings.HasSuffix(name, ".rar") {
		return "archive:rar"
	}
	if strings.HasSuffix(name, ".gz") {
		return "archive:gzip"
	}
	if strings.HasSuffix(name, ".xz") {
		return "archive:xz"
	}
	if strings.HasSuffix(name, ".zst") {
		return "archive:zstd"
	}
	if strings.HasSuffix(name, ".wasm") {
		return "executable:wasm"
	}
	if strings.HasSuffix(name, ".sh") || strings.HasSuffix(name, ".bash") || strings.HasSuffix(name, ".zsh") {
		return "script:posix-shell"
	}
	if strings.HasSuffix(name, ".ps1") {
		return "script:powershell"
	}
	if strings.HasSuffix(name, ".bat") || strings.HasSuffix(name, ".cmd") {
		return "script:windows-command"
	}
	if strings.HasSuffix(name, ".py") {
		return "script:python"
	}
	if strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".mjs") {
		return "script:javascript"
	}
	if strings.HasSuffix(name, ".vbs") {
		return "script:visual-basic"
	}
	if strings.HasSuffix(name, ".jar") {
		return "archive:java-jar"
	}
	if ext != "" {
		return "extension-unverified:" + strings.TrimPrefix(ext, ".")
	}
	return "unknown:extensionless"
}

func identifyMagic(b []byte) string {
	if bytes.HasPrefix(b, []byte("#!")) {
		return "script:interpreter"
	}
	switch {
	case len(b) >= 2 && b[0] == 'M' && b[1] == 'Z':
		return "executable:windows-pe"
	case len(b) >= 4 && bytes.Equal(b[:4], []byte{0x7f, 'E', 'L', 'F'}):
		return "executable:elf"
	case len(b) >= 4 && (bytes.Equal(b[:4], []byte{0xfe, 0xed, 0xfa, 0xce}) ||
		bytes.Equal(b[:4], []byte{0xce, 0xfa, 0xed, 0xfe}) ||
		bytes.Equal(b[:4], []byte{0xfe, 0xed, 0xfa, 0xcf}) ||
		bytes.Equal(b[:4], []byte{0xcf, 0xfa, 0xed, 0xfe}) ||
		bytes.Equal(b[:4], []byte{0xca, 0xfe, 0xba, 0xbe})):
		return "executable:mach-o-or-fat"
	case len(b) >= 4 && bytes.Equal(b[:4], []byte{0x50, 0x4b, 0x03, 0x04}):
		return "archive:zip"
	case len(b) >= 4 && bytes.Equal(b[:4], []byte{0x50, 0x4b, 0x05, 0x06}):
		return "archive:zip"
	case len(b) >= 4 && bytes.Equal(b[:4], []byte{0x50, 0x4b, 0x07, 0x08}):
		return "archive:zip"
	case len(b) >= 6 && bytes.Equal(b[:6], []byte{0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c}):
		return "archive:7zip"
	case len(b) >= 7 && bytes.Equal(b[:7], []byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00}):
		return "archive:rar4"
	case len(b) >= 8 && bytes.Equal(b[:8], []byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00}):
		return "archive:rar5"
	case len(b) >= 4 && bytes.Equal(b[:4], []byte{0x1f, 0x8b, 0x08, 0x00}):
		return "archive:gzip"
	case len(b) >= 6 && bytes.Equal(b[:6], []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}):
		return "archive:xz"
	case len(b) >= 4 && bytes.Equal(b[:4], []byte{0x28, 0xb5, 0x2f, 0xfd}):
		return "archive:zstd"
	case len(b) >= 4 && bytes.Equal(b[:4], []byte{0x4d, 0x53, 'C', 'F'}):
		return "container:cabinet"
	case len(b) >= 4 && bytes.Equal(b[:4], []byte{0xd0, 0xcf, 0x11, 0xe0}):
		return "container:ole"
	case len(b) >= 8 && bytes.Equal(b[:8], []byte{'!', '<', 'a', 'r', 'c', 'h', '>', '\n'}):
		return "package:debian-or-ar"
	case len(b) >= 4 && bytes.Equal(b[:4], []byte{0xed, 0xab, 0xee, 0xdb}):
		return "package:rpm"
	case len(b) >= 4 && bytes.Equal(b[:4], []byte{0x00, 0x61, 0x73, 0x6d}):
		return "executable:wasm"
	}
	if len(b) >= 262 && string(b[257:262]) == "ustar" {
		return "archive:tar"
	}
	return ""
}
