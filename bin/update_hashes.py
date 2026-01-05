#!/usr/bin/env python3
import subprocess
import json
import argparse
import os
import sys
import logging
from pathlib import Path
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def capture_file_state(directory=".", outdir: str = "."):
    """Capture current file state for verification

    Args:
        directory (str): Path to the directory containing the git repository
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
    """Main function to handle command-line arguments and execute git state capture"""
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
            logger.info(f"Package state captured successfully!")
            logger.info(f"Commit: {state['commit']}")
            logger.info(f"Files tracked: {len(state['file_hashes'])}")
            logger.info(f"Output saved to: {output_file}")
        else:
            logger.info(f"State saved to: {output_file}")

    except subprocess.CalledProcessError:
        logger.exception(f"Error running git command:")
        logger.error(f"Make sure '{args.directory}' is a valid git repository.")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
