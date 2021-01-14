#!/bin/sh

YEDB_VERSION=0.1.17

REQUIRED="realpath python3 curl"
MODS="cachetools==4.2.0 portalocker==2.0.0 jsonschema==3.2.0 yedb==${YEDB_VERSION} msgpack==1.0.2"

MODS_CLIENT="icli==0.0.10 neotermcolor==2.0.8 rapidtables==0.1.11 pyyaml==5.3.1 tqdm==4.55.1 pygments==2.7.3 getch==1.0"

[ -z "$YEDBD_BIND" ] && YEDBD_BIND=tcp://127.0.0.1:8870

if [ "$YEDBD_SERVICE" ]; then
  [ -z "$YEDB_PS" ] && YEDB_PS=$YEDBD_SERVICE
else
  YEDBD_SERVICE=yedbd
fi

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
  SETUP_VENV=1
  echo "Configuring VENV"
  ${PYTHON} -m venv ${FLAGS} "$DIR_ME/venv" || exit 2
else
  SETUP_VENV=0
fi

if [ "$NEED_PIP" = "1" ]; then
  (curl https://bootstrap.pypa.io/get-pip.py | "$DIR_ME/venv/bin/python") || exit 3
fi

if [ "$SETUP_VENV" = "1" ]; then
  "$DIR_ME/venv/bin/pip3" install -U wheel setuptools || exit 4
fi

"$DIR_ME/venv/bin/pip3" install -U $MODS $PIP_EXTRA_OPTIONS || exit 4
"$DIR_ME/venv/bin/pip3" install -U $MODS_CLIENT $PIP_EXTRA_OPTIONS || exit 4

mkdir -p "$DIR_ME/var" || exit 5
chmod 700 "$DIR_ME/var" || exit 5

(
cat > "$DIR_ME/yedb-server" << EOF
#!/bin/sh

case \$1 in

start)
  sh $DIR_ME/safe-run.sh > /dev/null 2>&1 &
  ;;
stop)
  kill "\$(cat "$DIR_ME/var/yedbd.pid")"
  ;;
*)
  echo "Usage: \$0 <start|stop>"
  ;;
esac

EOF
) || exit 6

(
cat > "$DIR_ME/safe-run.sh" << EOF
#!/bin/sh

while [ 1 ]; do
  "$DIR_ME/venv/bin/python3" -m yedb.server \\
  --pid-file "$DIR_ME/var/yedbd.pid" -B $YEDBD_BIND \\
  --default-fmt msgpack "$DIR_ME/var/db"
  if [ \$? -eq 0 ]; then
    break
  fi
done
EOF
) || exit 6

chmod +x "$DIR_ME/yedb-server" || exit 6

(
cat > "$DIR_ME/yedb" << EOF
#!/bin/sh

YEDB_PS="$YEDB_PS" "$DIR_ME/venv/bin/yedb" "$YEDBD_BIND" "\$@"
EOF
) || exit 6

chmod +x "$DIR_ME/yedb" || exit 6

if [ "$(id -u)" = "0" ]; then
  (
  if ! id -u yedb > /dev/null 2>&1; then
    useradd yedb -r -d "$DIR_ME"
  fi
  chown -R yedb "$DIR_ME/var" || exit 5
  cat > /etc/systemd/system/${YEDBD_SERVICE}.service << EOF
[Unit]
Description=YEDB daemon
After=network.target
StartLimitIntervalSec=0

[Service]
Type=forking
User=root
ExecStart=$DIR_ME/yedb-server start
PIDFile=$DIR_ME/var/yedbd.pid
Restart=no

[Install]
WantedBy=multi-user.target
EOF
) || exit 7
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
  echo "  sudo systemctl start $YEDBD_SERVICE"
  echo
fi

exit 0
