#!/bin/bash
DEST=$1
PKG=$2
PKG_UPLOAD_DIR=/tmp/pkg_upload

if [ "$PKG" == "all" ]
then
    PKG=*
fi

echo "Creating $PKG_UPLOAD_DIR on $DEST..."
docker exec $DEST mkdir $PKG_UPLOAD_DIR

echo "Getting local deb list..."
deb_upload_list=$(ls $PKG*.deb)

for deb_name in $deb_upload_list; do
    echo "Copying $deb_name up to $DEST..."
    docker cp $deb_name $DEST:$PKG_UPLOAD_DIR
done
# Get deb files to install:
echo "Populating list of deb to install from $PKG_UPLOAD_DIR..."
deb_list=$(docker exec $DEST ls $PKG_UPLOAD_DIR)

echo "List of installs needed: $deb_list"
for deb_name in $deb_list; do
    echo "Installing $deb_name on $DEST..."
    docker exec $DEST dpkg -i $PKG_UPLOAD_DIR/$deb_name
done

echo "Cleaning up $PKG_UPLOAD_DIR on $DEST..."
docker exec $DEST rm -rf $PKG_UPLOAD_DIR