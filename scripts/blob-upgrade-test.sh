#!/bin/bash
set -e
set -x

if [ -z "$PHONE" ]; then
    echo "usage: PHONE=<serial> ./blob_upgrade_test.sh"
    exit 1
fi

# Reset the device.
adb -s $PHONE  reboot-bootloader || true
cat ../../../prebuilts/locked_loaders/*$PHONE* \
    blob-v1.ec.RW_A.hex.signed blob-v1.ec.RW_B.hex.signed > /tmp/ec.hex
../../../prebuilts/linaro/4.9/arm-none-eabi-gcc/bin/arm-none-eabi-objcopy \
      -I ihex -O binary --gap-fill=0xff --pad-to=0xc0000 \
      /tmp/ec.hex /tmp/ec.bin
../../../core/nugget/util/rescue2/bin2rec /tmp/ec.bin /tmp/ec.rec
fastboot stage /tmp/ec.rec
fastboot oem citadel rescue
fastboot reboot -w
adb -s $PHONE  wait-for-device
adb -s $PHONE  root
adb -s $PHONE  shell /vendor/bin/hw/citadel_updater --suzyq 1 || true
adb -s $PHONE  shell /vendor/bin/hw/citadel_updater -v || grep red_v0.0.7669-d7a39373f+


# Generate key test.
adb -s $PHONE  shell /system/bin/keystore_cli_v2 delete-all
adb -s $PHONE  shell /system/bin/keystore_cli_v2 list
adb -s $PHONE  shell /system/bin/keystore_cli_v2 generate \
    --name=k1 --seclevel=strongbox
adb -s $PHONE  push dummy.plaintext /data
adb -s $PHONE  shell /system/bin/keystore_cli_v2 encrypt \
    --name=k1 --in=/data/dummy.plaintext --out=/data/dummy.ciphertext \
    --seclevel=strongbox
adb -s $PHONE  shell /system/bin/keystore_cli_v2 decrypt \
    --name=k1 --in=/data/dummy.ciphertext --out=/data/dummy.decrypted \
    --seclevel=strongbox
adb -s $PHONE  pull /data/dummy.decrypted /tmp
diff /tmp/dummy.decrypted dummy.plaintext

# Upgrade firmware.
adb -s $PHONE  root
adb -s $PHONE  push ../../../core/nugget/build/red/ec.bin /data/local/tmp/ec.bin
adb -s $PHONE  exec-out '/vendor/bin/hw/citadel_updater -v --rw --ro \
                /data/local/tmp/ec.bin'
adb -s $PHONE  exec-out \
    '/vendor/bin/hw/citadel_updater --enable_ro --enable_rw --reboot ""'
adb -s $PHONE  shell rm /data/local/tmp/ec.bin
adb -s $PHONE  shell /vendor/bin/hw/citadel_updater --suzyq 1 || true
adb -s $PHONE  shell /vendor/bin/hw/citadel_updater -lv | grep `cd ../../../core/nugget/; git log --oneline | head -1 | cut -d ' ' -f 1`

# Test upgraded blob.
adb -s $PHONE  shell /system/bin/keystore_cli_v2 decrypt \
    --name=k1 --in=/data/dummy.ciphertext --out=/data/dummy.decrypted \
    --seclevel=strongbox 

echo "PASS"
