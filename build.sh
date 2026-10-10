#!/usr/bin/env bash
# Build the plugin against the exact graylog.jar of graylog/graylog:$GRAYLOG_VERSION (default 7.1.10),
# inside a Maven + JDK 21 container. Output: dist/graylog-plugin-dnstap-<version>.jar
#   ./build.sh            build + unit tests
#   ./build.sh bench      also run the codec throughput micro-benchmark
#   ./build.sh analyze    also run Error Prone, SpotBugs + FindSecBugs and PMD (findings are reported, not fatal)
#   FUZZ_ITERATIONS=3000000 ./build.sh   longer fuzzing (default 300000)
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
V=${GRAYLOG_VERSION:-7.1.10}
MVN_IMAGE=maven:3.9.9-eclipse-temurin-21
mkdir -p .build/m2 dist
if [ ! -f ".build/graylog-$V.jar" ]; then
  echo "== extracting graylog.jar from graylog/graylog:$V"
  cid=$(docker create "graylog/graylog:$V"); docker cp -q "$cid:/usr/share/graylog/graylog.jar" ".build/graylog-$V.jar"; docker rm "$cid" >/dev/null
fi
extra=() goal=package
case ${1:-} in
  bench) extra=(-Dbench=true) ;;
  analyze) extra=(-Panalysis) goal=verify ;;
esac
[ -n "${FUZZ_ITERATIONS:-}" ] && extra+=("-Dfuzz.iterations=$FUZZ_ITERATIONS")   # e.g. FUZZ_ITERATIONS=3000000 ./build.sh
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD:/src" -w /src "$MVN_IMAGE" sh -ec "
  mvn -q -B -Dmaven.repo.local=/src/.build/m2 install:install-file -Dfile=.build/graylog-$V.jar \
      -DgroupId=org.graylog2 -DartifactId=graylog-server-bundle -Dversion=$V -Dpackaging=jar
  mvn -B -ntp -Dmaven.repo.local=/src/.build/m2 -Dgraylog.version=$V ${extra[*]:-} clean $goal"
rm -f dist/*.jar
cp "target/graylog-plugin-dnstap-$(sed -n "0,/<version>/s/.*<version>\(.*\)<\/version>.*/\1/p" pom.xml).jar" dist/   # only this build: two jars of the same plugin would conflict
ls -l dist/
