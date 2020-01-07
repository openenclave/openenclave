#!/bin/bash
mapfile -t <plugins/plugin-list
source plugins/install-plugins.sh "${MAPFILE[@]}"
