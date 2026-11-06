"""Writes the Windows resources of storii-tray (icon, manifest, version) as .syso COFF objects that `go build`
links in automatically, no dependencies:  python3 assets/make_winres.py VERSION
Reads the icon PNGs from cmd/storii-tray/icons (made by make_icons.py)."""
import os, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "cmd", "storii-tray")
SIZES = [16, 20, 24, 32, 40, 48, 64, 256]
LANG = 0x0409
RT_ICON, RT_GROUP_ICON, RT_VERSION, RT_MANIFEST = 3, 14, 16, 24

MANIFEST = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="sh.base2.storii.tray" version="{v}.0"/>
  <description>storii</description>
  <dependency><dependentAssembly>
    <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0"
      processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
  </dependentAssembly></dependency>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges>
    <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
  </requestedPrivileges></security></trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1"><application>
    <supportedOS Id="{{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}}"/>
  </application></compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3"><windowsSettings>
    <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
    <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
  </windowsSettings></application>
</assembly>
"""

def utf16z(s):
    return s.encode("utf-16-le") + b"\0\0"

def pad4(b):
    return b + b"\0" * (-len(b) % 4)

def block(key, value=b"", children=(), text=False):
    """One node of a VS_VERSIONINFO tree."""
    vlen = len(value) // 2 if text else len(value)
    raw = struct.pack("<HHH", 0, vlen, 1 if text else 0) + utf16z(key)
    raw = pad4(raw) + value
    for c in children:
        raw = pad4(raw) + c
    return struct.pack("<H", len(raw)) + raw[2:]

def version_info(v):
    parts = [int(x) for x in (v.split(".") + ["0"] * 4)[:4]]
    ms, ls = parts[0] << 16 | parts[1], parts[2] << 16 | parts[3]
    fixed = struct.pack("<13I", 0xFEEF04BD, 0x00010000, ms, ls, ms, ls, 0x3F, 0, 0x40004, 1, 0, 0, 0)
    strings = {"CompanyName": "base2", "FileDescription": "storii", "ProductName": "storii",
               "FileVersion": v, "ProductVersion": v, "OriginalFilename": "storii-tray.exe",
               "InternalName": "storii-tray", "LegalCopyright": "see LICENSE"}
    table = block("040904B0", children=[block(k, utf16z(s), text=True) for k, s in strings.items()], text=True)
    sfi = block("StringFileInfo", children=[table], text=True)
    vfi = block("VarFileInfo", children=[block("Translation", struct.pack("<HH", LANG, 1200))], text=True)
    return block("VS_VERSION_INFO", fixed, [sfi, vfi])

def resources(v):
    """{type: {id: bytes}}"""
    icons, group = {}, struct.pack("<HHH", 0, 1, len(SIZES))
    for i, s in enumerate(SIZES, 1):
        png = open(os.path.join(OUT, "icons", f"icon-{s}.png"), "rb").read()
        icons[i] = png
        group += struct.pack("<BBBBHHIH", s % 256, s % 256, 0, 0, 1, 32, len(png), i)
    return {RT_ICON: icons, RT_GROUP_ICON: {1: group}, RT_VERSION: {1: version_info(v)},
            RT_MANIFEST: {1: MANIFEST.format(v=v).encode()}}

def rsrc(res):
    """The .rsrc section: three directory levels (type, id, language), data entries, then the data.
    Returns the bytes and the offsets of the data entries' RVA fields, which need relocations."""
    types = sorted(res)
    dir_size = lambda n: 16 + 8 * n
    # Layout: root dir, one id-level dir per type, one language dir per resource, data entries, data.
    off = dir_size(len(types))
    type_dirs = {}
    for t in types:
        type_dirs[t] = off
        off += dir_size(len(res[t]))
    lang_dirs = {}
    for t in types:
        for i in sorted(res[t]):
            lang_dirs[t, i] = off
            off += dir_size(1)
    entries = {}
    for t in types:
        for i in sorted(res[t]):
            entries[t, i] = off
            off += 16
    data_off = {}
    for t in types:
        for i in sorted(res[t]):
            off += -off % 8
            data_off[t, i] = off
            off += len(res[t][i])
    buf = bytearray(off)
    def put_dir(at, items):
        struct.pack_into("<IIHHHH", buf, at, 0, 0, 0, 0, 0, len(items))
        for n, (ident, target, is_dir) in enumerate(items):
            struct.pack_into("<II", buf, at + 16 + 8 * n, ident, target | (0x80000000 if is_dir else 0))
    put_dir(0, [(t, type_dirs[t], True) for t in types])
    relocs = []
    for t in types:
        put_dir(type_dirs[t], [(i, lang_dirs[t, i], True) for i in sorted(res[t])])
        for i in sorted(res[t]):
            put_dir(lang_dirs[t, i], [(LANG, entries[t, i], False)])
            struct.pack_into("<IIII", buf, entries[t, i], data_off[t, i], len(res[t][i]), 0, 0)
            relocs.append(entries[t, i])
            buf[data_off[t, i]:data_off[t, i] + len(res[t][i])] = res[t][i]
    return bytes(buf), relocs

def coff(machine, reloc_type, section, relocs):
    hdr, sec = 20, 40
    raw_at = hdr + sec
    rel_at = raw_at + len(section)
    sym_at = rel_at + 10 * len(relocs)
    out = struct.pack("<HHIIIHH", machine, 1, 0, sym_at, 1, 0, 0)
    out += struct.pack("<8sIIIIIIHHI", b".rsrc", 0, 0, len(section), raw_at, rel_at, 0, len(relocs), 0, 0x40000040)
    out += section
    for r in relocs:
        out += struct.pack("<IIH", r, 0, reloc_type)
    out += struct.pack("<8sIhHBB", b".rsrc", 0, 1, 0, 3, 0)  # the section symbol relocations point at
    return out + struct.pack("<I", 4)  # empty string table

if __name__ == "__main__":
    version = sys.argv[1] if len(sys.argv) > 1 else "2.0.0"
    section, relocs = rsrc(resources(version))
    for arch, machine, rel in (("amd64", 0x8664, 3), ("arm64", 0xAA64, 2)):  # IMAGE_REL_*_ADDR32NB
        open(os.path.join(OUT, f"rsrc_windows_{arch}.syso"), "wb").write(coff(machine, rel, section, relocs))
