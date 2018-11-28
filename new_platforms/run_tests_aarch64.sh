export ARCH=aarch64
export MACHINE=virt

chmod +x ./new_platforms/build_optee.sh
./new_platforms/build_optee.sh || exit 1

wget https://tcpsbuild.blob.core.windows.net/tcsp-build/OE-CI-Ubuntu-16.04-AARCH64.tar.xz || exit 1
tar xvf OE-CI-Ubuntu-16.04-AARCH64.tar.xz || exit 1

cd ci
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
        
mkdir $HOME/.ssh
ssh-keygen -f $HOME/.ssh/known_hosts -R "[localhost]:5555"
ssh-keyscan -p 5555 localhost >> $HOME/.ssh/known_hosts

sshpass -p test ssh test@localhost -p 5555 -vvv "su -c \"mkdir /mnt/oe && mount -t 9p -o trans=virtio sh0 /mnt/oe -oversion=9p2000.L && cp /mnt/oe/new_platforms/bin/optee/tests/3156152a-19d1-423c-96ea-5adf5675798f.ta /lib/optee_armtz && /mnt/oe/new_platforms/tests/oetests_host/oetests_host \""
