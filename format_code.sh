#!/bin/bash

find . -name "*.py" | while read f; do autopep8 -i $f; done

