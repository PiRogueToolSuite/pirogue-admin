#!/bin/sh
set -e

s=$(dpkg-parsechangelog -SSource)
v=$(dpkg-parsechangelog -SVersion)
dist=$(dpkg-parsechangelog -SDistribution)

if [ "$dist" = UNRELEASED ]; then
  echo "E: please finalize the changelog (dch -r)"
  exit 1
fi

git tag -sm "Tagging $s v$v" "$s-v$v" "$@"
