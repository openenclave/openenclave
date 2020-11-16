# CodeQL Static Analysis on Open Enclave

## CodeQL Introduction
CodeQL is the static analysis engine used by developers to automate security checks, and by security researchers to perform variant analysis.

Unlike traditional static analysis tools CodeQL provides an ability to extend the analysis via custom queries in addition to the built-in queries.

## Running CodeQL analysis on Open Enclave
1. Run scripts/init.sh to download CodeQL library repoistory and CodeQL CLI.
2. Run scripts/run.sh which builds the CodeQL database and executes OpenEnclave custom queries on it. At the end of the scan it generates the results in SARIF format (OpenEnclave.sarif).
3. Install [CodeQL extension for Visual Studio Code](https://marketplace.visualstudio.com/items?itemName=GitHub.vscode-codeql) or [SARIF viewer extension](https://marketplace.visualstudio.com/items?itemName=WDGIS.MicrosoftSarifViewer).
4. Open OpenEnclave.sarif in Visual Studio Code to see results in results tab.

## To run a selected query in Visual Studio Code
1. Add the database (openenclave-codeql-db) in CodeQL extension.
2. Navigate to queries/cpp/openenclave and select a query.
3. Right-click a query and select "Run Queries in selected files" or Open the query annd select "CodeQL: Run a query" in Ctrl+Shift+P.

**References to learn more about CodeQL:**
* [CodeQL Introduction](https://help.semmle.com/codeql/about-codeql.html)
* [QL Language basics](https://help.semmle.com/QL/learn-ql/beginner/ql-tutorials.html)
* [CodeQL for C and C++](https://help.semmle.com/QL/learn-ql/cpp/ql-for-cpp.html)
* [CodeQL Library](https://github.com/github/codeql)
* [Samples](https://github.com/github/codeql/tree/main/cpp/ql/examples/snippets)
* [CodeQL for Visual Studio Code](https://help.semmle.com/codeql/codeql-for-vscode.html)
