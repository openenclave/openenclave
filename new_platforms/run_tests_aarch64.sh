export ARCH=aarch64
export MACHINE=virt

echo [CI] Building Open Enclave

chmod +x ./new_platforms/build_optee.sh
./new_platforms/build_optee.sh || exit 1

echo [CI] Installing Prerequistes

apt install sshpass -y

echo [CI] Downloading Emulated Environment

CI_DIR=ci
CI_ENV=OE-CI-Ubuntu-16.04-AARCH64

if [ ! -d $CI_DIR ]; then
    if [ ! -f $CI_ENV.tar.xz ]; then
        wget https://tcpsbuild.blob.core.windows.net/tcsp-build/$CI_ENV.tar.xz || exit 1
    fi
    tar xvf $CI_ENV.tar.xz --no-same-owner || exit 1
fi

echo [CI] Launching QEMU

cd $CI_DIR
nohup ./qemu-system-aarch64 \
        -nographic \
        -serial file:ree.log -serial file:tee.log \
        -smp 1 \
        -machine virt,secure=on -cpu cortex-a57 \
        -m 1057 \
        -bios bl1.bin \
        -semihosting-config enable,target=native \
        -d unimp \
        -initrd rootfs.cpio.gz \
        -kernel Image \
        -no-acpi \
        -append 'console=ttyAMA0,38400 keep_bootcon root=/dev/vda2' \
        -netdev user,id=net0,hostfwd=tcp::5555-:22 -device virtio-net,netdev=net0 \
        -virtfs local,id=sh0,path=$PWD/..,security_model=passthrough,readonly,mount_tag=sh0 &
disown

sleep 60

echo [CI] Connecting to QEMU Guest
        
mkdir $HOME/.ssh
ssh-keygen -f $HOME/.ssh/known_hosts -R "[localhost]:5555"

echo [CI] Retrieving Keys from QEMU Guest

ssh-keyscan -T 400 -p 5555 localhost >> $HOME/.ssh/known_hosts

echo [CI] Running Test Suite in QEMU Guest

sshpass -p test ssh test@localhost -p 5555 -vvv "su -c \"mkdir /mnt/oe && mount -t 9p -o trans=virtio sh0 /mnt/oe -oversion=9p2000.L && cp /mnt/oe/new_platforms/bin/optee/tests/3156152a-19d1-423c-96ea-5adf5675798f.ta /lib/optee_armtz && /mnt/oe/new_platforms/tests/oetests_host/oetests_host \"" || exit 2

pkill -9 qemu-system-aar
