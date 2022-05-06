#!/bin/bash
##
## Compile support-diagnostics and install if no errors.
##
TARGET=$1

# Break target down by commas into an array.
TARGET_ADDRESSES=()
while IFS=',' read -ra ADDRESSES; do
    for address in "${ADDRESSES[@]}"; do
        TARGET_ADDRESSES+=($address)
    done
done <<< "$TARGET"

for target_address in "${TARGET_ADDRESSES[@]}"; do
    echo "Copying to $target_address..."
    if [ -d /etc/untangle ]; then
        ##
        ## Building on ngfw system.
        ##
        dpkg-buildpackage -b -rfakeroot -us -uc

        if [ $? -eq 0 ] ; then
            dpkg -i ..//untangle-python3-support-diagnostics*deb
        fi
    else
        ##
        ## mfw.
        ##
        ssh-copy-id root@$target_address
        rsync -r -a -v --chown=root:root bin root@$target_address:/usr
        rsync -r -a -v --chown=root:root support_diagnostics/* root@$target_address:/usr/lib/python3.7/site-packages/support_diagnostics
    fi
done
