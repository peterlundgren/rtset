#!/bin/bash

failures=0

function assert_pass {
    if [ $? -ne 0 ]; then
        ((failures++))
        echo $1
    fi
}

function assert_fail {
    if [ $? -eq 0 ]; then
        ((failures++))
        echo $1
    fi
}

function assert_equals {
    if [ "$1" != "$2" ]; then
        ((failures++))
        echo \"$1\" not equal to \"$2\"
    fi
}

function end_test {
    echo "$failures failures"
    # Exit with the total number of failures. Cap at 127.
    if [ $failures -gt 127 ]; then
        exit 127
    else
        exit $failures
    fi
}
