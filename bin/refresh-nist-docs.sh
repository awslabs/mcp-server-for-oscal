#!/bin/bash

#==============================================================================
# OSCAL Documentdataion download script
#==============================================================================
# This script downloads and NIST OSCAL documentation from GitHub.
# https://github.com/usnistgov/OSCAL-Pages
#
# Purpose:
#   - Pulls the latest docs into the project for indexing
#
# Usage: ./bin/refresh-nist-docs.sh
#
# The script will:
#   1. Download zip archive of project from GitHub
#   2. Extracts a subset of content for indexing by bin/build_oscal_db.py
#==============================================================================

# Determine script directory using POSIX-compliant method
# This ensures the script works regardless of where it's called from
SCRIPT_DIR="$(CDPATH="" cd -- "$(dirname -- "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Define the target directory where OSCAL docs will be stored
# This is where the DB build script will look for content to index
DEST_DIR="$PROJECT_ROOT/data/oscal_docs"

# Release URL
RELEASE_URL="https://github.com/usnistgov/OSCAL-Pages/archive/refs/heads/main.zip"

# Determine temporary download directory
# Uses system temp directory (TMPDIR, TMP, TEMP, or defaults to /tmp)
# DOWNLOAD_DIR=${TMPDIR:-${TMP:-${TEMP:-/tmp}}}
DOWNLOAD_DIR=${PROJECT_ROOT}/tmp
mkdir "${DOWNLOAD_DIR}"

# Extract filename from the URL for local storage
RELEASE_FILE_NAME=$(basename "$RELEASE_URL")

# Download the repository archive
# -L flag follows redirects, -o specifies output file
echo "Downloading docs from: $RELEASE_URL"
curl -L -o "$DOWNLOAD_DIR"/"$RELEASE_FILE_NAME" $RELEASE_URL || { echo "FAIL 4"; exit 4; }

# Extract relevant files from the archive to destination
# unzip: -d specifies destination directory; -o overwrites existing files
echo "Extracting release zip to: $DEST_DIR"
unzip -o "${DOWNLOAD_DIR}/${RELEASE_FILE_NAME}" 'OSCAL-Pages-main/src/content/learn/concepts/*' -d "$DEST_DIR" || { echo "FAIL 3"; exit 3; }

# Clean up: remove the downloaded archive file
echo "Cleaning up temporary files..."
rm -rf "${DOWNLOAD_DIR}"

echo "SUCCESS!"
