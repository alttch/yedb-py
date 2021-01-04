#!/bin/bash -x

if [ -z "$2" ]; then
  echo "Usage: $0 lxc_image version"
  exit 1
fi

eval $(grep -E "^YEDB_VERSION|^MODS" ../setup-server.sh)

MODS="$MODS $MODS_CLIENT"

rm -rf "dist-$1-$2"
mkdir -p "dist-$1-$2"

CONTAINER=$(echo yedb-build-$1-$2|tr "." "-")

lxc delete -f "$CONTAINER"> /dev/null 2>&1

lxc launch "images:$1/$2" "$CONTAINER" || exit 1
sleep 2

if lxc exec "$CONTAINER" -- which apt-get > /dev/null; then
  lxc exec "$CONTAINER" -- apt-get install -y --no-install-recommends python3 python3-dev python3-pip gcc || exit 1
  lxc exec "$CONTAINER" -- pip3 install -U setuptools || exit 1
else
  lxc exec "$CONTAINER" -- yum install -y python3 python3-devel python3-pip gcc || exit 1
  lxc exec "$CONTAINER" -- yum install -y g++ || \
    lxc exec "$CONTAINER" -- yum install -y gcc-c++ || exit 1
fi

lxc exec "$CONTAINER" -- pip3 install $MODS pyinstaller==4.1 cbor==1.0.0 python-rapidjson==0.9.1 || exit 1
lxc exec "$CONTAINER" -- mkdir /opt/yedb || exit 1

lxc file push yedb-cli.py "$CONTAINER"/opt/yedb/ || exit 1
lxc file push yedb-server.py "$CONTAINER"/opt/yedb/ || exit 1

lxc exec "$CONTAINER" --cwd /opt/yedb -- env PYTHONOPTIMIZE=1 pyinstaller yedb-cli.py --onefile --nowindow --strip || exit 2
lxc exec "$CONTAINER" --cwd /opt/yedb -- env PYTHONOPTIMIZE=1 pyinstaller yedb-server.py --onefile --nowindow --strip || exit 2

lxc file pull "$CONTAINER"/opt/yedb/dist/yedb-cli "dist-$1-$2/yedb" || exit 3
lxc file pull "$CONTAINER"/opt/yedb/dist/yedb-server "dist-$1-$2/" || exit 3

lxc delete -f "$CONTAINER"

which figlet > /dev/null && figlet -m small Completed || echo COMPLETED
