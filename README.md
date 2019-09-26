# Repository for deployment of Homer

This repository will be deployed via scap, and it uses wheels (packaged as a
distro-specific tar.gz in the artifacts directory) to distribute its
dependencies.

## How to build the wheels

Assuming you have docker installed and your user is able to launch docker
containers, whenever your requirements change you just need to run

    make -f Makefile.build all

that will refresh the frozen requirements list re-download the correct wheels,
rebuild the ones needed, and package them for your next deploy.
