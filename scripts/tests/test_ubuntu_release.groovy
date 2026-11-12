// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// Run from the repository root: groovy scripts/tests/test_ubuntu_release.groovy
// Evaluate the actual shared library with only Jenkins I/O steps stubbed.
def helpers = new GroovyShell().parse(new File('.jenkins/library/vars/helpers.groovy'))
def contents = ''
def reads = 0
helpers.metaClass.readFile = { Map options ->
    assert options.file == '/etc/os-release'
    reads++
    contents
}
helpers.metaClass.sh = { Object ignored ->
    throw new AssertionError('Version lookup must not launch a shell'.toString())
}
helpers.metaClass.error = { String message ->
    throw new IllegalArgumentException(message)
}

[
    ['NAME="Ubuntu"\nVERSION_ID="22.04"\n', '22.04'],
    ['VERSION_ID=20.04\n', '20.04'],
    ["VERSION_ID='18.04'\n", '18.04'],
    ['VERSION_ID="24.04"\r\n', '24.04'],
    ['# VERSION_ID="18.04"\nVERSION_ID="22.04"\n', '22.04']
].each { fixture ->
    contents = fixture[0]
    assert helpers.getUbuntuReleaseVer() == fixture[1]
}
assert reads == 5

['', 'NAME=Ubuntu\n', 'VERSION_ID=\n', 'VERSION_ID=""\n',
 'VERSION_ID="22.04\n', 'VERSION_ID=$(lsb_release -rs)\n'].each { fixture ->
    contents = fixture
    def rejected = false
    try {
        helpers.getUbuntuReleaseVer()
    } catch (IllegalArgumentException expected) {
        rejected = true
    }
    assert rejected : "Malformed OS metadata must fail"
}

// Preserve agent-read failures rather than silently selecting an SGX device path.
def disconnected = new IOException('agent unavailable')
helpers.metaClass.readFile = { Map ignored -> throw disconnected }
def propagated = false
try {
    helpers.getUbuntuReleaseVer()
} catch (IOException expected) {
    assert expected.is(disconnected)
    propagated = true
}
assert propagated
println 'Ubuntu release helper: 12 checks passed; no shell launch'
