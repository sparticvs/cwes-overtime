#!/bin/bash
if [ $# -ne 1 ]
then
   echo "Needs a file to parse, should be something like a c9s-image-manifest.txt file" 
   exit 1
fi

## IDK, this is not working like it should - Python does the RegEx correctly,
## bash and grep just fail since there is !- (a valid historical command
## reference). Will fix later - ctimko

cat $1 | grep -oE '^([\/_a-zA-Z]|(?<!-)\d|-(?!\d))+'
