#!/bin/bash

#==============================================================================
# OSCAL Schema Update Script
#==============================================================================
# This script downloads and updates OSCAL (Open Security Controls Assessment 
# Language) schemas from the official NIST OSCAL GitHub repository.
#
# Purpose:
#   - Downloads the latest OSCAL schema files (JSON and XSD formats)
#   - Updates the local schema directory used by the MCP server
#   - Ensures the server has access to current OSCAL model definitions
#
# Usage: ./bin/update-oscal-schemas.sh
#
# The script will:
#   1. Download OSCAL v1.1.3 release package from GitHub
#   2. Extract JSON schema files and XSD files 
#   3. Place them in the project's schema directory
#   4. Clean up temporary download files
#==============================================================================

# Determine script directory using POSIX-compliant method
# This ensures the script works regardless of where it's called from
SCRIPT_DIR="$(CDPATH="" cd -- "$(dirname -- "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CURRENT_RELEASE_VERSION="1.2.0"

# Define the target directory where OSCAL schemas will be stored
# This is where the MCP server will look for schema definitions
SCHEMAS_DIR="$PROJECT_ROOT/src/mcp_server_for_oscal/oscal_schemas"

# OSCAL release URL - points to official NIST OSCAL v1.1.3 release
# Contains JSON schemas, XSD files, and other OSCAL model definitions
OSCAL_RELEASE_URL="https://github.com/usnistgov/OSCAL/releases/download/v$CURRENT_RELEASE_VERSION/oscal-$CURRENT_RELEASE_VERSION.zip"

# Determine temporary download directory
# Uses system temp directory (TMPDIR, TMP, TEMP, or defaults to /tmp)
DOWNLOAD_DIR=${TMPDIR:-${TMP:-${TEMP:-/tmp}}}

# Extract filename from the URL for local storage
OSCAL_RELEASE_FILE_NAME=$(basename "$OSCAL_RELEASE_URL")

# Download the OSCAL release archive
# -L flag follows redirects, -o specifies output file
echo "Downloading OSCAL schemas from: $OSCAL_RELEASE_URL"
curl -L -o "$DOWNLOAD_DIR"/"$OSCAL_RELEASE_FILE_NAME" $OSCAL_RELEASE_URL

# Extract only JSON and XSD files from the archive
# -d specifies destination directory
# -j flattens directory structure (junk paths)
# -o overwrites existing files
# "*.json" "*.xsd" filters to only extract schema files
echo "Extracting schema files to: $SCHEMAS_DIR"
unzip -j -o "${DOWNLOAD_DIR}/${OSCAL_RELEASE_FILE_NAME}" "*.json" "*.xsd" -d "$SCHEMAS_DIR" 

# Remove all white space from json files
for json_file in "$SCHEMAS_DIR"/*.json; do
    jq -c . "$json_file" > "$SCHEMAS_DIR"/tmpws.json && mv "$SCHEMAS_DIR"/tmpws.json "$json_file"
done

# Clean up: remove the downloaded archive file
echo "Cleaning up temporary files..."
rm -f "$SCHEMAS_DIR"/tmpws.json
rm -f "${DOWNLOAD_DIR}/${OSCAL_RELEASE_FILE_NAME}"

echo "OSCAL schema update completed successfully!"
