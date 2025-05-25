#!/bin/sh
set -e

commit=${1:-HEAD}

s=$(git show $commit:./debian/changelog | dpkg-parsechangelog -l- -SSource)
v=$(git show $commit:./debian/changelog | dpkg-parsechangelog -l- -SVersion)
dist=$(git show $commit:./debian/changelog | dpkg-parsechangelog -l- -SDistribution)
date=$(git show $commit:./debian/changelog | dpkg-parsechangelog -l- -SDate)

if [ "$dist" = UNRELEASED ]; then
  echo "E: please finalize the changelog (dch -r)"
  exit 1
fi

faketime "$date" git tag -sm "Tagging $s v$v" "$s-v$v" "$commit"
