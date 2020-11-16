#!/bin/bash
PROJECT=openenclave
REPO_ROOT=$(git rev-parse --show-toplevel)
PROJECT_PATH="$REPO_ROOT"
BUILD_PATH="$REPO_ROOT/build"
STATIC_PATH="$REPO_ROOT/tests/security/static"
PROJECT_CODEQL_DB="$PROJECT-codeql-db"
PROJECT_CODEQL_DB_PATH="$BUILD_PATH/$PROJECT_CODEQL_DB"
CODEQL_CLI_VERSION=$(<"$STATIC_PATH/scripts/codeql.config")
CODEQL_CLI_PATH="$BUILD_PATH/tools/codeql-cli/linux/$CODEQL_CLI_VERSION/codeql"
CODEQL_LIBRARY_PATH="$BUILD_PATH/codeql"
OE_SUITES_PATH="$STATIC_PATH/queries/cpp/suites"
OE_AND_CODEQL_BUILTIN_QUERIES="oe-codeql-security-queries.qls"
OE_QUERIES_ONLY="oe-security-queries-only.qls"
REBUILD=false
SCAN_BUILTIN_QUERIES=false

for args in "$@"
do
    case $args in
        -b|--built-in) SCAN_BUILTIN_QUERIES=true; shift ;;
        -r|--rebuild) REBUILD=true; shift ;;
        -h|--help|*)
            echo "-h, --help : Shows this message";
            echo "-b, --built-in : To Scan OE with built in queries";
            echo "-r, --rebuild : To rebuild CodeQL database";
        exit 1 ;;
    esac
    shift
done

if [ ! -d "$CODEQL_CLI_PATH" ]; then
    bash "$STATIC_PATH/scripts/init.sh"
fi

if [ ! -d "$PROJECT_CODEQL_DB_PATH" ] || $REBUILD; then
    [ -d "$PROJECT_PATH/_lgtm_build_dir" ] && rm -rf "$PROJECT_PATH/_lgtm_build_dir"
    [ -f "$PROJECT_PATH/_lgtm_detected_source_root" ] && rm "$PROJECT_PATH/_lgtm_detected_source_root"
    [ -d "$PROJECT_CODEQL_DB_PATH" ] && rm -rf "$PROJECT_CODEQL_DB_PATH"
    
    echo "Start building CodeQL database: $PROJECT_CODEQL_DB_PATH"
    cd "$PROJECT_PATH"
    "$CODEQL_CLI_PATH"/codeql database create "$PROJECT_CODEQL_DB_PATH" --search-path "$CODEQL_LIBRARY_PATH" --language=cpp --threads=8
    
    if [[ $? != 0 ]]; then
        echo "Failed to build CodeQL database for $PROJECT"
        exit 1
    fi
    
    echo "Completed building CodeQL database: $PROJECT_CODEQL_DB_PATH"
fi

if [ ! -d "$PROJECT_CODEQL_DB_PATH" ]; then
    echo "CodqQL databse: $PROJECT_CODEQL_DB_PATH is not found"
    exit 1
fi

echo "Upgrading database $PROJECT_CODEQL_DB_PATH"
"$CODEQL_CLI_PATH"/codeql database upgrade "$PROJECT_CODEQL_DB_PATH" --search-path "$CODEQL_LIBRARY_PATH" --threads=8

if [ ! -d "$PROJECT_CODEQL_DB_PATH" ]; then
    echo "CodqQL databse: $PROJECT_CODEQL_DB_PATH is not found"
    exit 1
fi

QUERIES="$OE_SUITES_PATH/$OE_QUERIES_ONLY"
if $SCAN_BUILTIN_QUERIES; then
    QUERIES="$OE_SUITES_PATH/$OE_AND_CODEQL_BUILTIN_QUERIES"
fi

echo "Query Suite: $QUERIES"
echo "Starting analysis on database $PROJECT_CODEQL_DB_PATH"
"$CODEQL_CLI_PATH"/codeql database analyze \
"$PROJECT_CODEQL_DB_PATH" \
"$QUERIES" \
--search-path "$CODEQL_LIBRARY_PATH" \
--format=sarif-latest \
--threads=8 \
--output="$BUILD_PATH/$PROJECT.sarif"

if [[ $? != 0 ]]; then
    echo "Failed to analyze $PROJECT_CODEQL_DB_PATH"
    exit 1
fi

echo "Completed analysis on $PROJECT_CODEQL_DB_PATH"
exit 0
