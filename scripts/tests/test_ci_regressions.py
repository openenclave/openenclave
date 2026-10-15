# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

"""Offline regression checks for the actual CI shell and download helper."""

import hashlib
import http.server
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading
import unittest


ROOT = Path(__file__).resolve().parents[2]


class TestCommandTests(unittest.TestCase):
    def run_command(self, failures, failure_count=1, regex="", debug=False):
        helpers = (ROOT / ".jenkins/library/vars/helpers.groovy").read_text()
        function = helpers.split("def TestCommand(", 1)[1].split(
            "def createOpenEnclavePackageCommand", 1
        )[0]
        shell = re.search(r'return """(.*?)"""', function, re.S).group(1)
        # Render the command's GString; execute its real shell body, not a copy.
        arguments = "--tests-regex '{}'".format(regex) if regex else ""
        if debug:
            arguments += " -VV --debug"
        shell = shell.replace("${regex}", arguments)
        shell = shell.replace("${globalvars.CTEST_TIMEOUT_SECONDS}", "480")
        shell = shell.replace("${test_fail_limit}", "10").replace("\\$", "$")
        self.assertNotIn("${debug}", shell)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            fake = path / "ctest"
            fake.write_text(
                "#!/usr/bin/env bash\n"
                "count=0\n"
                "if [ -f count ]; then count=$(cat count); fi\n"
                "count=$((count+1)); echo $count > count\n"
                "printf '%s\\n' \"$*\" >> arguments\n"
                "if [ $count -le \"$FAILURES\" ]; then\n"
                "  if [ \"$FAILURE_COUNT\" -ge 0 ]; then\n"
                "    mkdir -p Testing/Temporary\n"
                "    : > Testing/Temporary/LastTestsFailed.log\n"
                "    for ((i=0;i<FAILURE_COUNT;i++)); do\n"
                "      echo '1:regression' >> Testing/Temporary/LastTestsFailed.log\n"
                "    done\n"
                "  fi\n"
                "  exit 8\n"
                "fi\n"
                "exit 0\n"
            )
            fake.chmod(0o755)
            env = dict(os.environ, PATH=directory + os.pathsep + os.environ["PATH"])
            env.update(FAILURES=str(failures), FAILURE_COUNT=str(failure_count))
            result = subprocess.run(
                ["bash", "-e", "-o", "pipefail", "-c", shell + "\necho NEXT_STEP"],
                cwd=directory, env=env, capture_output=True, text=True, timeout=30
            )
            count = int((path / "count").read_text())
            args = (path / "arguments").read_text().splitlines()
            self.assertTrue(all("false" not in arg and "true" not in arg for arg in args))
            return result, count, args

    def test_initial_success(self):
        result, count, _ = self.run_command(0)
        self.assertEqual((result.returncode, count), (0, 1))
        self.assertIn("NEXT_STEP", result.stdout)

    def test_retry_success(self):
        result, count, args = self.run_command(2, regex="^tests/crypto/", debug=True)
        self.assertEqual((result.returncode, count), (0, 3))
        self.assertIn("--rerun-failed", args[1])
        self.assertIn("--tests-regex ^tests/crypto/ -VV --debug", args[1])

    def test_exhausted_retries_fail(self):
        result, count, _ = self.run_command(10)
        self.assertEqual((result.returncode, count), (8, 4))
        self.assertNotIn("NEXT_STEP", result.stdout)

    def test_failure_limit(self):
        result, count, _ = self.run_command(10, failure_count=11)
        self.assertEqual((result.returncode, count), (8, 1))

    def test_missing_failure_log(self):
        result, count, _ = self.run_command(10, failure_count=-1)
        self.assertEqual((result.returncode, count), (8, 1))


class DownloadTests(unittest.TestCase):
    def check_download(self, responses, cached=None):
        payload = b"verified SGX header fixture\n"
        requests = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                code, data = responses[min(len(requests) - 1, len(responses) - 1)]
                self.send_response(code)
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *_args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory)
                target = path / "sgx.h"
                if cached is not None:
                    target.write_bytes(cached)
                script = path / "download.cmake"
                script.write_text(
                    'cmake_minimum_required(VERSION 3.12)\n'
                    'include("{}/cmake/download_verified.cmake")\n'
                    'oe_download_verified("http://127.0.0.1:{}/sgx.h" "{}" "{}")\n'.format(
                        ROOT.as_posix(), server.server_port, target.as_posix(),
                        hashlib.sha256(payload).hexdigest()
                    )
                )
                result = subprocess.run(
                    ["cmake", "-P", str(script)], capture_output=True, text=True, timeout=30
                )
                data = target.read_bytes() if target.exists() else None
                self.assertFalse((path / "sgx.h.download").exists())
                return result, len(requests), data
        finally:
            server.shutdown()
            thread.join()
            server.server_close()

    def test_transient_http_error(self):
        payload = b"verified SGX header fixture\n"
        result, count, data = self.check_download([(503, b"unavailable"), (200, payload)])
        self.assertEqual((result.returncode, count, data), (0, 2, payload))

    def test_verified_cache_is_offline(self):
        payload = b"verified SGX header fixture\n"
        result, count, data = self.check_download([(503, b"unavailable")], cached=payload)
        self.assertEqual((result.returncode, count, data), (0, 0, payload))

    def test_bad_cache_is_replaced(self):
        payload = b"verified SGX header fixture\n"
        result, count, data = self.check_download([(200, payload)], cached=b"bad cache")
        self.assertEqual((result.returncode, count, data), (0, 1, payload))

    def test_checksum_failure_is_fatal(self):
        result, count, data = self.check_download([(200, b"untrusted contents")])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA256 mismatch", result.stderr)
        self.assertEqual((count, data), (1, None))

    def test_persistent_http_error_is_fatal(self):
        result, count, data = self.check_download([(503, b"unavailable")])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((count, data), (3, None))


if __name__ == "__main__":
    unittest.main()
