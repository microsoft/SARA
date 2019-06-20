#!/bin/bash

apk=$1
package=$2

apktool d $1 -o unpacked_apk
rm -r ./unpacked_apk/original
python ./parse_project.py --path ./unpacked_apk --package $2
rm -r ./unpacked_apk
