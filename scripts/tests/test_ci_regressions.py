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


class AzureLinuxCheckoutTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name)
        self.pipeline = (
            ROOT / ".jenkins/infrastructure/docker/build_linux_docker_images.Jenkinsfile"
        ).read_text()
        preview = self.pipeline.split("if (params.BUILD_AZL3_SDK_PREVIEW)", 1)[1]
        self.preflight = re.search(r"sh '''(.*?)'''", preview, re.S).group(1)

    def git(self, directory, *arguments):
        return subprocess.run(
            ["git", "-c", "protocol.file.allow=always", "-c", "user.name=CI Test",
             "-c", "user.email=ci-test@example.invalid", *arguments],
            cwd=directory, check=True, capture_output=True, text=True, timeout=30
        )

    def repository(self, name):
        directory = self.path / name
        directory.mkdir()
        self.git(directory, "init")
        self.git(directory, "commit", "--allow-empty", "-m", "Fixture")
        return directory

    def checkout(self, initialize=True):
        leaf = self.repository("leaf")
        dependency = self.repository("dependency")
        self.git(dependency, "submodule", "add", str(leaf), "nested")
        self.git(dependency, "commit", "-am", "Add nested dependency")
        source = self.repository("source")
        self.git(source, "submodule", "add", str(dependency), "dependency")
        self.git(source, "commit", "-am", "Add dependency")
        checkout = self.path / "checkout"
        self.git(self.path, "clone", str(source), str(checkout))
        if initialize:
            self.git(checkout, "submodule", "update", "--init", "--recursive")
        return checkout

    def check_preflight(self, directory):
        return subprocess.run(
            ["bash", "-e", "-c", self.preflight + "\necho BUILD_REACHED"],
            cwd=directory, capture_output=True, text=True, timeout=30
        )

    def assert_rejected(self, directory):
        result = self.check_preflight(directory)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("BUILD_REACHED", result.stdout)

    def test_checkout_initializes_pinned_submodules(self):
        checkout = self.pipeline.split('stage("Checkout")', 1)[1].split(
            'stage("Install Azure CLI")', 1
        )[0]
        self.assertIn("$class: 'SubmoduleOption'", checkout)
        self.assertIn("disableSubmodules: false", checkout)
        self.assertIn("recursiveSubmodules: true", checkout)
        self.assertIn("trackingSubmodules: false", checkout)

    def test_pinned_recursive_checkout_passes(self):
        result = self.check_preflight(self.checkout())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("BUILD_REACHED", result.stdout)

    def test_uninitialized_submodule_is_rejected(self):
        self.assert_rejected(self.checkout(initialize=False))

    def test_uninitialized_nested_submodule_is_rejected(self):
        checkout = self.checkout()
        self.git(checkout / "dependency", "submodule", "deinit", "-f", "nested")
        self.assert_rejected(checkout)

    def test_wrong_submodule_commit_is_rejected(self):
        checkout = self.checkout()
        self.git(checkout / "dependency", "commit", "--allow-empty", "-m", "Wrong revision")
        self.assert_rejected(checkout)

    def test_git_failure_stops_build(self):
        self.assert_rejected(self.path)

    def test_sdk_build_selects_clang(self):
        preview = self.pipeline.split("if (params.BUILD_AZL3_SDK_PREVIEW)", 1)[1]
        self.assertIn("-DCMAKE_C_COMPILER=clang", preview)
        self.assertIn("-DCMAKE_CXX_COMPILER=clang++", preview)
        self.assertLess(preview.index(self.preflight), preview.index("oeazl3.inside("))


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
    def check_download(self, responses, cached=None, mirror=False):
        payload = b"verified SGX header fixture\n"
        requests = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                code, data = responses[min(len(requests) - 1, len(responses) - 1)]
                self.send_response(code)
                self.send_header("X-Private-Test", "do-not-log-this-header")
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
                    'oe_download_verified("http://127.0.0.1:{}/sgx.h" "{}" "{}" {})\n'.format(
                        ROOT.as_posix(), server.server_port, target.as_posix(),
                        hashlib.sha256(payload).hexdigest(),
                        '"http://127.0.0.1:{}/mirror.h"'.format(server.server_port) if mirror else ""
                    )
                )
                result = subprocess.run(
                    ["cmake", "-P", str(script)], capture_output=True, text=True, timeout=30
                )
                data = target.read_bytes() if target.exists() else None
                self.assertFalse((path / "sgx.h.download").exists())
                self.assertNotIn("do-not-log-this-header", result.stdout + result.stderr)
                if mirror and len(requests) >= 2:
                    self.assertEqual(requests[:2], ["/sgx.h", "/mirror.h"])
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
        self.assertIn("HTTP/1.0 503", result.stdout + result.stderr)

    def test_upstream_mirror_after_http_error(self):
        payload = b"verified SGX header fixture\n"
        result, count, data = self.check_download([(403, b"blocked"), (200, payload)], mirror=True)
        self.assertEqual((result.returncode, count, data), (0, 2, payload))
        self.assertIn("HTTP/1.0 403", result.stdout)

    def test_mirror_does_not_bypass_checksum(self):
        result, count, data = self.check_download([(403, b"blocked"), (200, b"wrong bytes")], mirror=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA256 mismatch", result.stderr)
        self.assertEqual((count, data), (2, None))

    def test_all_upstreams_unavailable_is_fatal(self):
        result, count, data = self.check_download([(503, b"unavailable")], mirror=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((count, data), (6, None))

    def test_verified_cache_does_not_contact_mirror(self):
        payload = b"verified SGX header fixture\n"
        result, count, data = self.check_download(
            [(503, b"unavailable")], cached=payload, mirror=True
        )
        self.assertEqual((result.returncode, count, data), (0, 0, payload))

    def test_primary_checksum_failure_does_not_try_mirror(self):
        payload = b"verified SGX header fixture\n"
        result, count, data = self.check_download(
            [(200, b"wrong bytes"), (200, payload)], mirror=True
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((count, data), (1, None))


if __name__ == "__main__":
    unittest.main()
