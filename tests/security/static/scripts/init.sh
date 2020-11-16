#!/bin/bash
REPO_ROOT=$(git rev-parse --show-toplevel)
BUILD_PATH="$REPO_ROOT/build"
STATIC_PATH="$REPO_ROOT/tests/security/static"
CODEQL_CLI_VERSION=$(<"$STATIC_PATH/scripts/codeql.config")
CODEQL_CLI_PLATFORM_PATH="$BUILD_PATH/tools/codeql-cli/linux"
CODEQL_CLI_PATH="$CODEQL_CLI_PLATFORM_PATH/$CODEQL_CLI_VERSION"
CODEQL_CLI_URL=https://github.com/github/codeql-cli-binaries/releases/download/$CODEQL_CLI_VERSION/codeql-linux64.zip
CODEQL_LIBRARY_PATH="$BUILD_PATH/codeql"

if [ ! -d "$CODEQL_LIBRARY_PATH" ]; then
    git clone https://github.com/github/codeql.git "$CODEQL_LIBRARY_PATH"
    cd "$CODEQL_LIBRARY_PATH"
    # Reset to rc/1.25
    git reset 589a097197075384a46340a3b3202a3e8ecb3272
fi

if [ ! -d "$CODEQL_CLI_PLATFORM_PATH" ]; then
    mkdir -p "$CODEQL_CLI_PLATFORM_PATH"
    if [[ $? != 0 ]]; then
        echo "Failed to create $CODEQL_CLI_PLATFORM_PATH"
        exit 1
    fi
fi

if [ -d "$CODEQL_CLI_PATH" ]; then
    echo "CodeQL $CODEQL_CLI_VERSION is already downloaded"
    exit 0
fi

mkdir "$CODEQL_CLI_PATH"
if [[ $? != 0 ]]; then
    echo "Failed to create $CODEQL_CLI_PATH"
    exit 1
fi

cd "$CODEQL_CLI_PATH"
echo "Downloading latest CodeQL CLI $CODEQL_CLI_VERSION"
wget --show-progress $CODEQL_CLI_URL

if [[ $? != 0 ]]; then
    echo "Failed to download $CODEQL_CLI_PATH"
    exit 1
fi

echo "Extracting CodeQL CLI"
unzip codeql-linux64.zip
if [[ $? != 0 ]]; then
    echo "Failed to extract CodeQL CLI $CODEQL_CLI_PATH"
    exit 1
fi

echo "Successfully download $CODEQL_CLI_VERSION"
exit 0
