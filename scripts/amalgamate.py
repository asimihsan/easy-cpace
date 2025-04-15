import argparse
import os
import re
import sys
from pathlib import Path

# --- Configuration ---
# These paths are relative to the project root determined by the script's location
CPACE_INTERNAL_HEADERS = [
    "src/crypto_iface/crypto_provider.h",
    "src/common/debug.h",
    "src/common/utils.h",
    "src/cpace_core/cpace_core.h",
]

CPACE_SOURCES = [
    "src/common/utils.c",
    "src/crypto_backend_monocypher/monocypher_backend.c",
    "src/cpace_core/cpace_core.c",
    "src/cpace_api/cpace_api.c",
]

# These will be relative to the monocypher_dir argument
MONOCYPHER_HEADERS = [
    "monocypher.h",
    "optional/monocypher-ed25519.h",
]

MONOCYPHER_SOURCES = [
    "monocypher.c",
    "optional/monocypher-ed25519.c",
]

PUBLIC_API_HEADER = "include/easy_cpace.h"

# Regex to find include guards (simple version)
INCLUDE_GUARD_RE = re.compile(r"^\s*#\s*(ifndef|define|endif).*\n", re.MULTILINE)
# Regex to find internal includes ("...")
INTERNAL_INCLUDE_RE = re.compile(r'^\s*#\s*include\s*"([^"]+)"', re.MULTILINE)
# Regex to find standard includes (<...>)
STANDARD_INCLUDE_RE = re.compile(r"^\s*#\s*include\s*<([^>]+)>", re.MULTILINE)


def get_file_content(filepath: Path) -> str:
    """Reads a file, exits on error."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        print(f"ERROR: File not found: {filepath}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Reading file {filepath}: {e}", file=sys.stderr)
        sys.exit(1)


def strip_include_guards(content: str) -> str:
    """Removes simple #ifndef/#define/#endif include guards."""
    # A basic removal strategy
    content = re.sub(r"^\s*#\s*ifndef\s+\w+\s*\n", "", content, flags=re.MULTILINE)
    content = re.sub(r"^\s*#\s*define\s+\w+\s*\n", "", content, flags=re.MULTILINE)
    content = re.sub(
        r"^\s*#\s*endif\s*(/\*.*?\*/)?\s*\n", "", content, flags=re.MULTILINE
    )
    return content


def main():
    parser = argparse.ArgumentParser(description="Amalgamate easy_cpace library.")
    parser.add_argument(
        "--monocypher-dir",
        type=Path,
        required=True,
        help="Path to the Monocypher source directory (e.g., build/_deps/monocypher-src/src).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("dist"),
        help="Directory to place amalgamated files.",
    )
    parser.add_argument(
        "--debug", action="store_true", help="Enable CPACE_DEBUG_LOG define."
    )
    args = parser.parse_args()

    project_root = Path(__file__).parent.parent.resolve()
    output_dir = args.output_dir
    monocypher_dir = args.monocypher_dir

    output_h = output_dir / "easy_cpace_amalgamated.h"
    output_c = output_dir / "easy_cpace_amalgamated.c"

    if not monocypher_dir.is_dir():
        print(
            f"ERROR: Monocypher directory not found: {monocypher_dir}", file=sys.stderr
        )
        sys.exit(1)

    # Create output directory if it doesn't exist
    output_dir.mkdir(parents=True, exist_ok=True)

    print("Starting amalgamation...")
    print(f"  Project Root: {project_root}")
    print(f"  Monocypher Dir: {monocypher_dir}")
    print(f"  Output Dir: {output_dir}")
    print(f"  Debug Logging: {'Enabled' if args.debug else 'Disabled'}")

    internal_header_content = ""
    all_source_content = ""
    standard_includes = set()

    # --- 1. Process internal headers (CPace + Monocypher) ---
    print("Processing internal headers...")
    all_internal_headers = [project_root / h for h in CPACE_INTERNAL_HEADERS] + [
        monocypher_dir / h for h in MONOCYPHER_HEADERS
    ]

    for header_path in all_internal_headers:
        print(f"  Processing header: {header_path.relative_to(project_root)}")
        content = get_file_content(header_path)
        internal_header_content += strip_include_guards(content) + "\n\n"
        # Find standard includes within headers
        for match in STANDARD_INCLUDE_RE.finditer(content):
            standard_includes.add(f"#include <{match.group(1)}>")

    # --- 2. Process source files (CPace + Monocypher) ---
    print("Processing source files...")
    all_source_files = [project_root / s for s in CPACE_SOURCES] + [
        monocypher_dir / s for s in MONOCYPHER_SOURCES
    ]

    for src_path in all_source_files:
        print(f"  Processing source: {src_path.relative_to(project_root)}")
        content = get_file_content(src_path)
        # Remove internal includes ("...") as their content is already gathered
        content = INTERNAL_INCLUDE_RE.sub("", content)
        # Collect standard includes (<...>)
        for match in STANDARD_INCLUDE_RE.finditer(content):
            standard_includes.add(f"#include <{match.group(1)}>")

        all_source_content += f"\n/* --- Start of content from {src_path.name} --- */\n"
        all_source_content += content.strip()  # Remove extra whitespace
        all_source_content += f"\n/* --- End of content from {src_path.name} --- */\n\n"

    # --- 3. Generate .c file ---
    print(f"Generating {output_c}...")
    with open(output_c, "w", encoding="utf-8") as f_c:
        f_c.write("/*\n * EasyCPace Amalgamated Source File\n")
        f_c.write(" * Generated by scripts/amalgamate.py.\n *\n")
        f_c.write(" * Contains code from:\n")
        f_c.write(
            " *   - EasyCPace (https://github.com/asimihsan/easy_cpace) - MPL-2.0 License\n"
        )
        f_c.write(
            " *   - Monocypher v4.0.2 (https://monocypher.org) - CC0 1.0 or BSD 2-Clause License\n"
        )
        f_c.write(" *\n * See respective project licenses for details.\n */\n\n")

        # Add configuration defines
        if args.debug:
            f_c.write("/* Configuration Defines */\n")
            f_c.write("#ifndef CPACE_DEBUG_LOG\n")
            f_c.write("#define CPACE_DEBUG_LOG 1\n")
            f_c.write("#endif\n\n")
        # Platform defines are handled by #ifdefs within monocypher_backend.c

        # Write standard includes
        f_c.write("/* Standard Library Includes */\n")
        for inc in sorted(list(standard_includes)):
            f_c.write(f"{inc}\n")
        f_c.write("\n")

        # Write internal headers (definitions and prototypes)
        f_c.write("/* --- Start Internal Header Definitions --- */\n\n")
        f_c.write(internal_header_content.strip())
        f_c.write("\n\n/* --- End Internal Header Definitions --- */\n\n")

        # Write source code
        f_c.write("/* --- Start Source Code --- */\n\n")
        f_c.write(all_source_content.strip())
        f_c.write("\n\n/* --- End Source Code --- */\n")

    # --- 4. Generate .h file ---
    print(f"Generating {output_h}...")
    public_api_path = project_root / PUBLIC_API_HEADER
    public_api_content = get_file_content(public_api_path)

    with open(output_h, "w", encoding="utf-8") as f_h:
        f_h.write("/*\n * EasyCPace Amalgamated Header File\n")
        f_h.write(" * Generated by scripts/amalgamate.py.\n *\n")
        f_h.write(" * Contains code from:\n")
        f_h.write(
            " *   - EasyCPace (https://github.com/asimihsan/easy_cpace) - MPL-2.0 License\n"
        )
        f_h.write(
            " *   - Monocypher v4.0.2 (https://monocypher.org) - CC0 1.0 or BSD 2-Clause License\n"
        )
        f_h.write(" *\n * See respective project licenses for details.\n */\n\n")

        f_h.write("#ifndef EASY_CPACE_AMALGAMATED_H\n")
        f_h.write("#define EASY_CPACE_AMALGAMATED_H\n\n")

        # Add necessary standard includes from the public API header
        f_h.write("/* Public API Includes */\n")
        api_standard_includes = set()
        for match in STANDARD_INCLUDE_RE.finditer(public_api_content):
            api_standard_includes.add(f"#include <{match.group(1)}>")
        for inc in sorted(list(api_standard_includes)):
            f_h.write(f"{inc}\n")
        f_h.write("\n")

        f_h.write("/* Public API Declarations */\n")
        # Strip include guards from the public API content before pasting
        public_api_content_stripped = strip_include_guards(public_api_content)
        # Remove standard includes as they are handled above
        public_api_content_stripped = STANDARD_INCLUDE_RE.sub(
            "", public_api_content_stripped
        )

        f_h.write(public_api_content_stripped.strip())
        f_h.write("\n\n#endif /* EASY_CPACE_AMALGAMATED_H */\n")

    print("\nAmalgamation complete.")
    print(f"  Generated: {output_h}")
    print(f"  Generated: {output_c}")


if __name__ == "__main__":
    main()
