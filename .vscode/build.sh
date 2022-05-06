#!/bin/bash
PKG=$1
CLEAN_ARTIFACTS=$2

if [ "$PKG" == "all" ]
then
    PKG=*
fi

if [ "$CLEAN_ARTIFACTS" == "yes" ]
then
    rm -f *.buildinfo \
    && rm -f *.changes \
    && rm -f *.deb \
    && rm -f *.tar.xz \
    && rm -f *.dsc \
    && rm -f *.orig.tar.xz
fi

PKGTOOLS_COMMIT=origin/master docker-compose -f docker-compose.build.yml run pkgtools
PACKAGE=$PKG FORCE=1 VERBOSE=1 UPLOAD=local docker-compose -f docker-compose.build.yml run build