#!/bin/bash
DEST=$1
PKG=$2
DEST_USR=$3

if [ -z "${DEST}" ]
then
    echo "Missing destination"
    exit
fi

if [ -z "${DEST_USR}" ]
then
    DEST_USR=root
fi

if [ "$PKG" == "all" ]
then
    PKG=*
    DEST_PKG=""
else
    DEST_PKG=$PKG.deb
fi
echo "Checking key updates on $DEST..."
ssh-copy-id $DEST_USR@$DEST

echo "Creating tmp directories on $DEST..."
ssh $DEST_USR@$DEST mkdir -p /tmp/pkg_upload/

echo "Uploading packages: $PKG to $DEST..."
scp $PKG*.deb $DEST_USR@$DEST:/tmp/pkg_upload/$DEST_PKG

echo "Installing packages: $PKG to $DEST..."
ssh $DEST_USR@$DEST dpkg -i /tmp/pkg_upload/$PKG.deb

echo "Cleaning up packages on $DEST..."
ssh $DEST_USR@$DEST rm /tmp/pkg_upload/$PKG.deb
