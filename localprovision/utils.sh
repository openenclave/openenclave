function retry_download() {
  retries=$1; wait_sleep=$2; timeout=$3; url=$4; path=$5 checksum=$6
  for i in $(seq 1 $retries); do
    rm -f $path
    timeout $timeout curl -fsSL $url -o $path
    if [ $? -ne 0 ]; then
      echo "retry_download[$i] Error: Failed to execute curl -fsSL $url -o $path"
      sleep $wait_sleep
      continue
    fi
    if [ ! -z "${checksum:-}" ]; then
      actual=$(sha1sum -b $path | cut -f 1 -d " ")
      if [ $? -ne 0 ]; then
        echo "retry_download[$i] Error: Failed to execute sha1sum -b $path (per $url)"
        sleep $wait_sleep
        continue
      fi
      if [ "$checksum" != "$actual" ]; then
        echo "retry_download[$i] Error: sha1sum mismatch for $url"
        sleep $wait_sleep
        continue
      fi
    fi
    echo "Successfully downloaded $url ($checksum) after $i attempts"
    return 0
  done
  echo "Failed to download $url ($checksum) after $retries attempts"
  return 1
}

function retrycmd_if_failure() {
    retries=$1; wait_sleep=$2; timeout=$3; shift && shift && shift
    for i in $(seq 1 $retries); do
        timeout $timeout ${@}
        [ $? -eq 0 ] && break || \
        if [ $i -eq $retries ]; then
            echo "Error: Failed to execute \"$@\" after $i attempts"
            return 1
        else
            sleep $wait_sleep
        fi
    done
    echo Executed \"$@\" $i times;
}

function retry_get_install_deb() {
  retries=$1; wait_sleep=$2; timeout=$3; url=$4; checksum=$5
  deb=$(mktemp)
  trap "rm -f $deb" RETURN
  retry_download $retries $wait_sleep $timeout $url $deb $checksum
  if [ $? -ne 0 ]; then
    echo "Error: Failed to download $url"
    return 1
  fi
  retrycmd_if_failure $retries $wait_sleep $timeout dpkg -i $deb
  if [ $? -ne 0 ]; then
    echo "Error: Failed to install $url"
    return 1
  fi
}
