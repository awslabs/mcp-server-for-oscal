#!/bin/bash

#==============================================================================
# OSCAL Schema Update Script
#==============================================================================
# This script downloads and updates AWS Component Definitions from GitHub.
# https://github.com/awslabs/oscal-content-for-aws-services
#
# Purpose:
#   - Pulls the $CURRENT_RELEASE_VERSION of AWS Component Definitions into the project
#
# Usage: ./bin/update-aws-cdefs.sh
#
# The script will:
#   1. Download specified release package from GitHub
#   2. Extracts and minifies the Component Definitions
#   3. Creates a new zip of the resulting Component Definitions
#==============================================================================

# Determine script directory using POSIX-compliant method
# This ensures the script works regardless of where it's called from
SCRIPT_DIR="$(CDPATH="" cd -- "$(dirname -- "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CURRENT_RELEASE_VERSION="0.1.0"

# Define the target directory where OSCAL schemas will be stored
# This is where the MCP server will look for schema definitions
DEST_DIR="$PROJECT_ROOT/src/mcp_server_for_oscal/component_definitions"

# Release URL
RELEASE_URL="https://github.com/awslabs/oscal-content-for-aws-services/releases/download/v$CURRENT_RELEASE_VERSION/oscal-content-for-aws-services-$CURRENT_RELEASE_VERSION.zip"

# Determine temporary download directory
# Uses system temp directory (TMPDIR, TMP, TEMP, or defaults to /tmp)
# DOWNLOAD_DIR=${TMPDIR:-${TMP:-${TEMP:-/tmp}}}
DOWNLOAD_DIR=${PROJECT_ROOT}/tmp
mkdir "${DOWNLOAD_DIR}"

# Extract filename from the URL for local storage
RELEASE_FILE_NAME=$(basename "$RELEASE_URL")

# Download the OSCAL release archive
# -L flag follows redirects, -o specifies output file
echo "Downloading release from: $RELEASE_URL"
curl -L -o "$DOWNLOAD_DIR"/"$RELEASE_FILE_NAME" $RELEASE_URL

# Extract files from the archive and move relevant ones to destination
# unzip: -d specifies destination directory; -o overwrites existing files
echo "Extracting release zip to: $DOWNLOAD_DIR"
unzip -o "${DOWNLOAD_DIR}/${RELEASE_FILE_NAME}" -d "$DOWNLOAD_DIR" 

# Remove all white space from json files
WORK_DIR="${DOWNLOAD_DIR}/oscal-content-for-aws-services-0.1.0/component-definitions"
for json_file in "$WORK_DIR"/*.json "$WORK_DIR"/**/*.json; do
    jq -c . "$json_file" > "$WORK_DIR"/tmpws.json && mv "$WORK_DIR"/tmpws.json "$json_file"
done

cd "$WORK_DIR" || (echo "FAIL" && exit 1)
ZIP_FILE_TEMP_PATH="${DOWNLOAD_DIR}"/aws-component-definitions-v${CURRENT_RELEASE_VERSION}.zip
# Create a new zip containing only the relevant (component definition) files
zip -r "${ZIP_FILE_TEMP_PATH}" .
# Remove existing zip files from dest directory - we don't want multiple versions
rm -f "${DEST_DIR}"/aws-component-definitions*.zip
# Copy new zip to destination dir, overwriting existing files
cp -f "${ZIP_FILE_TEMP_PATH}" "${DEST_DIR}"

# Clean up: remove the downloaded archive file
echo "Cleaning up temporary files..."
rm -rf "${DOWNLOAD_DIR}"

echo "SUCCESS!"
