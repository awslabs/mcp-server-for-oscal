#!/usr/bin/env python3
"""
File Integrity Hash Generation Script

This script captures the current state of files in a directory by generating SHA-256 hashes
and recording the current Git commit hash. It creates a hashes.json file that can be used
later to verify file integrity using the verify_package_integrity() function in utils.py.

The script is designed to be run during build/packaging time to create a baseline for
security verification. The generated hashes.json file contains:
- Git commit hash of the current repository state
- SHA-256 hashes of all files in the specified directory (excluding hashes.json itself)

This implements the file integrity verification system specified in:
.kiro/specs/file-integrity-testing/requirements.md

Usage:
    `hatch run rehash` (preferred within the project; script defined in pyproject.toml)
    `./update_hashes.py <directory> [-o <output_directory>] [-v]`

Example:
    ./bin/update_hashes.py src/mcp_server_for_oscal/oscal_schemas
    ./bin/update_hashes.py docs/schemas -o build/integrity -v

The generated hashes.json can then be verified at runtime using:
    from mcp_server_for_oscal.tools.utils import verify_package_integrity
    verify_package_integrity(Path("src/mcp_server_for_oscal/oscal_schemas"))
"""
import argparse
import hashlib
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def capture_file_state(directory=".", outdir: str = "."):
    """Capture current file state for verification by generating SHA-256 hashes.

    This function creates a comprehensive snapshot of all files in the specified directory
    by computing SHA-256 hashes and recording the current Git commit. The resulting
    hashes.json file serves as a tamper-evident baseline for later integrity verification.

    The function implements the hash manifest generation requirements from:
    .kiro/specs/file-integrity-testing/requirements.md - Requirement 7 (Test Data Management)

    Args:
        directory (str): Path to the directory containing files to hash. Must be within
                        a Git repository for commit hash capture.
        outdir (str): Directory where the hashes.json file will be written. Defaults
                     to the same directory as the input directory.

    Returns:
        tuple: A tuple containing:
            - dict: The captured state with 'commit' and 'file_hashes' keys
            - str: Path to the generated hashes.json file

    Raises:
        subprocess.CalledProcessError: If Git command fails (e.g., not a Git repository)
        OSError: If file I/O operations fail
        PermissionError: If insufficient permissions to read files or write output

    Example:
        >>> state, output_file = capture_file_state("src/schemas", "build/integrity")
        >>> print(f"Captured {len(state['file_hashes'])} files to {output_file}")
        Captured 15 files to build/integrity/hashes.json

    Note:
        - The hashes.json file itself is excluded from hash calculation
        - Only regular files are processed (directories and special files are ignored)
        - Files are read in binary mode to ensure accurate hash computation
        - Git commit hash includes single quotes as returned by git log --format
    """
    # Resolve the absolute path
    directory = os.path.abspath(directory)
    """Capture current Git state for verification"""
    commit = subprocess.run(
        ["git", "log", "-1", "--format='%H'", "--", directory],
        capture_output=True,
        text=True,
        check=True,
        cwd=directory,
    ).stdout.strip()

    files = Path(directory).iterdir()
    file_hashes = {}
    for f in files:
        if f.is_file and f.name != "hashes.json":
            with open(f, "rb") as of:
                file_hashes[f.name] = hashlib.sha256(of.read()).hexdigest()

    state = {"commit": commit, "file_hashes": file_hashes}

    # Save hashes.json in the specified directory
    output_file = os.path.join(outdir, "hashes.json")
    with open(output_file, "w") as f:
        json.dump(state, f, indent=2)

    return state, output_file


def main():
    """Main function to handle command-line arguments and execute file state capture.
    
    This function provides the command-line interface for the file integrity hash
    generation script. It validates input arguments, processes the specified directory,
    and generates a hashes.json file for later integrity verification.
    
    The function implements comprehensive error handling and validation as specified in:
    .kiro/specs/file-integrity-testing/requirements.md - Requirement 5 (Error Handling)
    
    Command-line Arguments:
        directory: Required positional argument specifying the directory to process
        -v, --verbose: Optional flag to enable detailed output logging
        -o, --outdir: Optional directory where hashes.json will be written
    
    Exit Codes:
        0: Success - hashes.json generated successfully
        1: Error - Invalid arguments, missing directories, or processing failure
    
    Example Usage:
        python bin/update_hashes.py src/schemas
        python bin/update_hashes.py docs -o build/integrity -v
    
    The generated hashes.json file can be used with verify_package_integrity():
        from mcp_server_for_oscal.tools.utils import verify_package_integrity
        verify_package_integrity(Path("src/schemas"))
    """
    parser = argparse.ArgumentParser(
        description="Capture current state (commit hash and file hashes) for a specified directory"
    )
    parser.add_argument(
        "directory",
        help="Path to the directory containing the directory to process",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )
    parser.add_argument(
        "-o", "--outdir", help="Path to directory where output file will be written"
    )

    args = parser.parse_args()

    # Validate that the directories exist
    if not os.path.exists(args.directory):
        logger.error(f"Error: Directory '{args.directory}' does not exist.")
        sys.exit(1)

    if not os.path.isdir(args.directory):
        logger.error(f"Error: '{args.directory}' is not a directory.")
        sys.exit(1)

    if not args.outdir:
        args.outdir = args.directory

    if not os.path.exists(args.outdir):
        logger.error(f"Error: Output directory '{args.outdir}' does not exist.")
        sys.exit(1)

    if not os.path.isdir(args.outdir):
        logger.error(f"Error: Output directory '{args.outdir}' is not a directory.")
        sys.exit(1)

    try:
        if args.verbose:
            logger.info(
                f"Processing git repository at: {os.path.abspath(args.directory)}"
            )

        state, output_file = capture_file_state(args.directory, args.outdir)

        if args.verbose:
            logger.info("Package state captured successfully!")
            logger.info(f"Commit: {state['commit']}")
            logger.info(f"Files tracked: {len(state['file_hashes'])}")
            logger.info(f"Output saved to: {output_file}")
        else:
            logger.info(f"State saved to: {output_file}")

    except subprocess.CalledProcessError:
        logger.exception("Error running git command:")
        logger.error(f"Make sure '{args.directory}' is a valid git repository.")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
