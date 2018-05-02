#!/bin/bash
# Run PCAPAnalyzer jar
# Author: Matthieu Labas (2013)

# Determine the actual path of the script, as the PCAPAnalyzer.jar file is located with it (this is mandatory!)
PROG=$(basename "$0")
DIR=$(cd "$(dirname "$0")" && pwd)
# If the script we run is a link, follow it
if [ -h $DIR/$PROG ] ; then
	DIR=$DIR/$(dirname $(readlink $DIR/$PROG))
fi
JAVA_OPT=""
PROG_OPT=""
# Parse options to determine which ones are for Java and which ones are for the Program
while [ $# -gt 0 ] ; do
	case $1 in
		-Xm*) JAVA_OPT="$JAVA_OPT $1" ;;
		-D*)  JAVA_OPT="$JAVA_OPT $1" ;;
		*)    PROG_OPT="$PROG_OPT $1" ;;
	esac
	shift
done
java $JAVA_OPT -jar $DIR/PCAPAnalyzer.jar $PROG_OPT
