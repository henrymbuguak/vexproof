"""A finding with two candidate functions from one fix commit, like Pillow's shared ICO/ICNS fix."""

from __future__ import annotations

from vexproof.domain import Advisory, Candidate, Evidence, Finding, Level, Package

ICO = "PIL.IcoImagePlugin.IcoFile.frame"
ICNS = "PIL.IcnsImagePlugin.read_png_or_jpeg2000"
QUOTE = "excessive memory use for a crafted ICO file"


def ico_finding(*, level: Level = Level.L1_SYMBOL, details: str = "") -> Finding:
    candidates = (
        Candidate(
            qualname=ICO,
            module="PIL.IcoImagePlugin",
            file="PIL/IcoImagePlugin.py",
            changed_lines=3,
            commits=("756fff33",),
            diff="@@ -1 +1 @@\n-    data = fp.read(size)\n"
            "+    data = ImageFile._safe_read(fp, size)",
        ),
        Candidate(
            qualname=ICNS,
            module="PIL.IcnsImagePlugin",
            file="PIL/IcnsImagePlugin.py",
            changed_lines=2,
            commits=("756fff33",),
        ),
    )
    return Finding(
        id="pillow@4.3.0:GHSA-95q3-8gr9-gm8w",
        package=Package(name="pillow", version="4.3.0", direct=True),
        advisory=Advisory(
            id="GHSA-95q3-8gr9-gm8w",
            summary="Pillow excessive memory use for a crafted ICO file",
            details=details
            or "Pillow before 8.1.1 allows attackers to cause a denial of service (memory "
            "consumption) because the reported size of a contained image is not properly "
            "checked for an **ICO** container.",
        ),
        evidence=Evidence(level=level, candidates=candidates if level is Level.L1_SYMBOL else ()),
    )
