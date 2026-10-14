package scanner

import "testing"

func TestIdentifyFileTypeUsesMagicBeforeExtension(t *testing.T) {
	got := IdentifyFileType("looks-like-a.txt", []byte{0x7f, 'E', 'L', 'F', 0, 0})
	if got != "executable:elf" {
		t.Fatalf("IdentifyFileType() = %q, want executable:elf", got)
	}
}

func TestIdentifyFileTypeRecognizesExtensionlessELF(t *testing.T) {
	got := IdentifyFileType("program", []byte{0x7f, 'E', 'L', 'F'})
	if got != "executable:elf" {
		t.Fatalf("IdentifyFileType() = %q, want executable:elf", got)
	}
}

func TestIdentifyFileTypeExtensionIsOnlyFallbackHint(t *testing.T) {
	got := IdentifyFileType("renamed.exe", []byte("ordinary text"))
	if got != "executable:windows-pe" {
		t.Fatalf("extension fallback = %q", got)
	}
	got = IdentifyFileType("unknown-file", []byte("ordinary text"))
	if got != "unknown:extensionless" {
		t.Fatalf("extensionless fallback = %q", got)
	}
}

func TestIdentifyFileTypeCompoundExtensions(t *testing.T) {
	cases := map[string]string{
		"app.tar.gz": "archive:tar-gzip",
		"app.tar.xz": "archive:tar-xz",
		"app.tar.zst": "archive:tar-zstd",
		"installer.msixbundle": "package:windows-bundle",
		"release.flatpakref": "package:flatpak-reference",
	}
	for path, want := range cases {
		if got := IdentifyFileType(path, nil); got != want {
			t.Errorf("IdentifyFileType(%q) = %q, want %q", path, got, want)
		}
	}
}
