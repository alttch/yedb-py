#!/bin/sh

YEDB_VERSION=0.0.43

REQUIRED="realpath python3 curl"
MODS="yedb==${YEDB_VERSION} msgpack==1.0.2 aiohttp==3.7.3"

MODS_CLIENT="icli neotermcolor rapidtables pyyaml tqdm pygments requests==2.21.0 getch"

[ -z "$YEDBD_BIND" ] && YEDBD_BIND=http://127.0.0.1:8870

check_required_exec() {
  p=$1
  printf "Checking %s => " "$p"
  if ! RESULT=$(command -v "$p" 2>&1); then
    echo "Missing! Please install"
    return 1
  fi
  echo "${RESULT}"
  return 0
}

e=
for r in ${REQUIRED}; do
  check_required_exec "$r" || e=1
done
[ "$e" = 1 ] && exit 1

echo

DIR_ME=$(pwd)

[ -z "$PYTHON" ] && PYTHON=python3
[ -z "$PIP" ] && PIP=pip3

FLAGS=
NEED_PIP=

if ! command -v $PIP > /dev/null ; then
  FLAGS=--without-pip
  NEED_PIP=1
fi

if [ ! -d venv ]; then
  echo "Configuring VENV"
  ${PYTHON} -m venv ${FLAGS} "$DIR_ME/venv" || exit 2
  "$DIR_ME/venv/bin/pip3" install -U wheel setuptools || exit 2
fi

if [ "$NEED_PIP" = "1" ]; then
  (curl https://bootstrap.pypa.io/get-pip.py | "$DIR_ME/venv/bin/python") || exit 3
fi

"$DIR_ME/venv/bin/pip3" install -U $MODS $PIP_EXTRA_OPTIONS || exit 4
"$DIR_ME/venv/bin/pip3" install -U $MODS_CLIENT $PIP_EXTRA_OPTIONS || exit 4

mkdir -p "$DIR_ME/var" || exit 5
chmod 700 "$DIR_ME/var" || exit 5

(
cat > "$DIR_ME/yedb-server" << EOF
#!/bin/sh

"$DIR_ME/venv/bin/python3" -m yedb.async_server \\
--pid-file "$DIR_ME/var/yedbd.pid" -B $YEDBD_BIND \\
--default-fmt msgpack "$DIR_ME/var/db"
EOF
)|| exit 6

chmod +x "$DIR_ME/yedb-server" || exit 6

(
cat > "$DIR_ME/yedb" << EOF
#!/bin/sh

YEDB_PS="$YEDB_PS" "$DIR_ME/venv/bin/yedb" "$YEDBD_BIND" "\$@"
EOF
)|| exit 6

chmod +x "$DIR_ME/yedb" || exit 6

if [ "$(id -u)" = "0" ]; then
  (
  if ! id -u yedb > /dev/null; then
    useradd yedb -r -d "$DIR_ME"
  fi
  chown -R yedb "$DIR_ME/var" || exit 5
  cat > /etc/systemd/system/yedbd.service << EOF
[Unit]
Description=YEDB daemon
After=network.target
StartLimitIntervalSec=0
[Service]
Type=simple
Restart=always
RestartSec=1
User=yedb
ExecStart="$DIR_ME/yedb-server"

[Install]
WantedBy=multi-user.target
EOF
)  || exit 7
HAS_SERVICE=1
else
  echo
  echo "Running under the regular user. Skipped service configuration"
  HAS_SERVICE=0
fi

echo
echo "SETUP COMPLETED"

if [ "$HAS_SERVICE" = "1" ]; then
  echo
  echo "To start yedbd, type:"
  echo
  echo "  sudo systemctl start yedbd"
  echo
fi

exit 0
