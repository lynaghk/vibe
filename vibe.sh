#!/usr/bin/env bash

if [[ "--force" == "$1" ]]; then
  rm -v "$HOME/.cache/vibe/default.raw"
  rm -rfv .vibe
  shift
fi

set -euo pipefail
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ "$DIR/src/main.rs" -nt "$DIR/target/debug/vibe" ]; then
  bash -c "cd $DIR && cargo build"
elif [ "$DIR/src/bash_logout.sh" -nt "$DIR/target/debug/vibe" ]; then
  bash -c "cd $DIR && cargo build"
elif [ "$DIR/Cargo.toml" -nt "$DIR/target/debug/vibe" ]; then
  bash -c "cd $DIR && cargo build"
elif [ "$DIR/src/provision.sh" -nt "$DIR/target/debug/vibe" ]; then
  rm -v "$HOME/.cache/vibe/default.raw" || true
  rm -rfv .vibe || true
  bash -c "cd $DIR && cargo build"
else
  :
fi

"$DIR/target/debug/vibe" "$@"
