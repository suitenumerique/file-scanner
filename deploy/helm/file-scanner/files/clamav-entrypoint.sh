#!/bin/sh
# Starts freshclam and clamd without root. The image's own /init needs root
# (it chowns the database volume and edits /etc/clamav in place); this one
# copies the stock configuration into a writable directory, applies the
# CLAMD_CONF_<Option> environment the same way, fetches the signatures on an
# empty volume, then runs the two daemons as the container user.
set -eu

conf_dir="${CLAMAV_CONF_DIR:-/config}"
db_dir="${CLAMAV_DB_DIR:-/var/lib/clamav}"
clamd_conf="$conf_dir/clamd.conf"
freshclam_conf="$conf_dir/freshclam.conf"

cp /etc/clamav/clamd.conf "$clamd_conf"
cp /etc/clamav/freshclam.conf "$freshclam_conf"

# CLAMD_CONF_StreamMaxLength=2200M → "StreamMaxLength 2200M": replaces the
# option's line (commented or not), appends when the file has none.
env | grep '^CLAMD_CONF_' | while IFS='=' read -r key value; do
  option="${key#CLAMD_CONF_}"
  if grep -q "^#\\?$option " "$clamd_conf"; then
    sed -i "s|^#\\?$option .*|$option $value|" "$clamd_conf"
  else
    printf '%s %s\n' "$option" "$value" >> "$clamd_conf"
  fi
done

# clamd refuses to start without a database: fetch it in the foreground
# first. TestDatabases/NotifyClamd are off for that one run (no clamd yet).
if [ ! -f "$db_dir/main.cvd" ] && [ ! -f "$db_dir/main.cld" ]; then
  echo "Downloading the initial signature database"
  sed -e 's|^\(TestDatabases \)|#\1|' -e '$a TestDatabases no' \
      -e 's|^\(NotifyClamd \)|#\1|' \
      "$freshclam_conf" > "$conf_dir/freshclam_initial.conf"
  freshclam --foreground --stdout --config-file="$conf_dir/freshclam_initial.conf"
  rm -f "$conf_dir/freshclam_initial.conf"
fi

if [ "${CLAMAV_NO_FRESHCLAMD:-false}" != "true" ]; then
  echo "Starting freshclam"
  freshclam --checks="${FRESHCLAM_CHECKS:-1}" --daemon --foreground --stdout \
    --config-file="$freshclam_conf" &
fi

echo "Starting clamd"
exec clamd --foreground --config-file="$clamd_conf"
