"""Regressions for source-preserving ARM64 native compiler selection."""

import os
from pathlib import Path
import shutil
import struct
import subprocess
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "scripts/build.ps1").read_text(encoding="utf-8")
SETUP = SCRIPT.split("# Resolve the native compiler explicitly,", 1)[1].split(
    "if ($Phase -eq 'Prepare') {", 1)[0]
ARM64 = SETUP.split(
    "\nif ($Architecture -eq 'aarch64') {", 1)[1].split("\n}\n", 1)[0]


class CompilerSetupTests(unittest.TestCase):
    def test_only_arm64_target_uses_hosted_clang_cl(self):
        self.assertIn("$compiler = $msvcCompiler", SETUP)
        self.assertIn(
            "$compiler = Join-Path $env:ProgramFiles 'LLVM/bin/clang-cl.exe'",
            ARM64,
        )
        for name in ("CC", "CXX"):
            self.assertIn(f"$env:{name}_aarch64_pc_windows_msvc = $compiler", ARM64)
            self.assertNotRegex(SETUP, rf"\$env:{name}\s*=")
        self.assertIn("Test-Path -LiteralPath $compiler -PathType Leaf", ARM64)
        self.assertIn("throw 'Hosted LLVM clang-cl missing'", ARM64)
        self.assertIn(
            "Invoke-Checked $compiler @('--target=aarch64-pc-windows-msvc', '--version')",
            ARM64,
        )

    def test_msvc_sdk_linker_librarian_and_static_crt_are_retained(self):
        self.assertIn("-arch=$nativeArch -host_arch=x64", SETUP)
        self.assertIn("[Environment]::SetEnvironmentVariable", SETUP)
        for executable, variable in (
            ("cl.exe", "msvcCompiler"),
            ("link.exe", "linker"),
            ("lib.exe", "archiver"),
        ):
            self.assertIn(
                f"${variable} = (Get-Command {executable} -CommandType Application).Source",
                SETUP,
            )
        self.assertIn("$env:AR_aarch64_pc_windows_msvc = $archiver", ARM64)
        self.assertIn(
            "$env:CARGO_TARGET_AARCH64_PC_WINDOWS_MSVC_LINKER = $linker", ARM64
        )
        self.assertIn(
            "$env:CARGO_TARGET_AARCH64_PC_WINDOWS_MSVC_RUSTFLAGS = "
            "'-Ctarget-feature=+crt-static'",
            ARM64,
        )

    def test_identity_hashes_target_and_host_native_tools(self):
        native = next(line for line in SETUP.splitlines() if "native = " in line)
        for variable in ("compiler", "msvcCompiler", "linker", "archiver"):
            self.assertIn(f"Get-FileHash ${variable} -Algorithm SHA256", native)
        self.assertIn("CC($|_)", SETUP)
        self.assertIn("CXX($|_)", SETUP)
        self.assertIn("AR($|_)", SETUP)
        self.assertIn("CARGO_", SETUP)
        self.assertIn("$environment[$_.Name] = $_.Value", SETUP)

    def test_setup_is_shared_by_prepare_and_compile_without_source_edits(self):
        self.assertNotIn("$Phase", SETUP)
        self.assertNotRegex(SETUP, r"(?i)(Set-Content|WriteAllText|Out-File).*candidate")
        self.assertIn("'rev-parse', 'HEAD'", SCRIPT)
        self.assertIn("throw 'Wrong source commit'", SCRIPT)
        self.assertIn('throw "Non-exact submodule: $_"', SCRIPT)
        self.assertNotIn("PNG_ARM_NEON_OPT=0", SETUP)


@unittest.skipUnless(shutil.which("clang-cl"), "local LLVM clang-cl unavailable")
class LLVMArm64ObjectTests(unittest.TestCase):
    def setUp(self):
        self.scratch = ROOT / "tests/.arm64-compiler-work"
        self.work = self.scratch / uuid.uuid4().hex
        self.work.mkdir(parents=True)
        self.addCleanup(self.cleanup)

    def cleanup(self):
        shutil.rmtree(self.work)
        try:
            self.scratch.rmdir()
        except OSError:
            pass

    def compile(self, name, source):
        path = self.work / name
        path.write_text(source, encoding="utf-8")
        output = self.work / f"{name}.o"
        # cc-rs 1.4.2 uses -o for MSVC-like .S inputs and -Fo for C/C++.
        output_args = (
            ["-o", str(output)] if path.suffix == ".S" else ["-Fo" + str(output)]
        )
        environment = os.environ.copy()
        for name in ("CL", "_CL_"):
            environment.pop(name, None)
        result = subprocess.run(
            [
                shutil.which("clang-cl"), "--target=aarch64-pc-windows-msvc",
                "-nologo", "-MT", "-O2", "-Brepro", "/clang:-ffreestanding",
                *output_args, "-c", "--", str(path),
            ],
            env=environment, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(output.is_file(), result.stdout + result.stderr)
        data = output.read_bytes()
        self.assertEqual(struct.unpack_from("<H", data)[0], 0xAA64)
        return data

    def test_preprocessed_empty_assembly_emits_arm64_coff_object(self):
        # The pinned libpng stub emits no assembly for the default intrinsics
        # implementation: f5e92d76973a7a53f517579bc95d61483bf108c0,
        # arm/filter_neon.S:33-61; pngpriv.h:138-149.
        self.compile("placeholder.S", """
#if !defined(__aarch64__) || !defined(__clang__)
#error Wrong compiler target
#endif
#define PNG_ARM_NEON_IMPLEMENTATION 1
#if PNG_ARM_NEON_IMPLEMENTATION == 2
#error Hand-coded ARM32 assembler is not supported
#endif
""")

    def test_c_and_cpp_neon_intrinsics_emit_arm64_static_crt_objects(self):
        source = """
#include <arm_neon.h>
uint8x16_t add_neon(uint8x16_t a, uint8x16_t b) {
    return vaddq_u8(a, b);
}
"""
        for extension in ("c", "cpp"):
            with self.subTest(extension=extension):
                data = self.compile(f"neon.{extension}", source)
                self.assertIn(b"/defaultlib:libcmt", data.lower())
                self.assertNotIn(b"/defaultlib:msvcrt", data.lower())


if __name__ == "__main__":
    unittest.main()
