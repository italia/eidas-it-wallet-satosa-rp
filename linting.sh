#!/bin/bash

SRC="pyeudiw"

autopep8 -r --in-place $SRC
autoflake -r --in-place  --remove-unused-variables --expand-star-imports --remove-all-unused-imports $SRC

flake8 $SRC --count --select=E9,F63,F7,F82 --show-source --statistics
flake8 $SRC --max-line-length 120 --count --statistics

bandit -r -x $SRC/test* $SRC/*

echo -e '\nHTML:'
readarray -d '' array < <(find $SRC example -name "*.html" -print0)
echo "Running linter on (${#array[@]}): "
printf '\t- %s\n' "${array[@]}"
echo "Linter output:"

for file in "${array[@]}"
do
  echo -e "\n$file:"
  html_lint.py "$file" | awk -v path="file://$PWD/$file:" '$0=path$0' | sed -e 's/: /:\n\t/';
done

errors=0
for file in "${array[@]}"
do
  errors=$((errors + $(html_lint.py "$file" | grep -c 'Error')))
done

echo -e "\nHTML errors: $errors"
if [ "$errors" -gt 0 ]; then exit 1; fi;
