#!/bin/bash

source "./helpers.bash"

TEST_NET="cilium"

function cleanup {
	cilium policy delete 2> /dev/null || true
	docker rm -f foo foo bar baz 2> /dev/null || true
}

trap cleanup EXIT

cleanup
logs_clear

docker network inspect $TEST_NET 2> /dev/null || {
	docker network create --ipv6 --subnet ::1/112 --ipam-driver cilium --driver cilium $TEST_NET
}

echo "------ simple policy import ------"

cilium -D policy delete

cat <<EOF | cilium -D policy import -
[{
    "endpointSelector": ["role=frontend"]
}]
EOF

read -d '' EXPECTED_POLICY <<"EOF" || true
[
  {
    "endpointSelector": [
      {
        "key": "role",
        "value": "frontend",
        "source": "cilium"
      }
    ]
  }
]
EOF

DIFF=$(diff -Nru  <(cilium policy get root) <(echo "$EXPECTED_POLICY")) || true
if [[ "$DIFF" != "" ]]; then
	abort "$DIFF"
fi

cilium policy delete

echo "------ validate foo=>bar policy ------"

docker run -dt --net=$TEST_NET --name foo -l id.foo tgraf/netperf
docker run -dt --net=$TEST_NET --name bar -l id.bar tgraf/netperf
docker run -dt --net=$TEST_NET --name baz -l id.baz tgraf/netperf

cat <<EOF | cilium -D policy import -
[{
    "endpointSelector": ["id.bar"],
    "ingress": [{
        "fromEndpoints": [
	    ["reserved:host"], ["id.foo"]
	]
    }]
}]
EOF

read -d '' EXPECTED_POLICY <<"EOF" || true
NEW TRACE >> From: [cilium:id.foo] => To: [cilium:id.bar]
  Required labels not found
  Found all required labels
END TRACE << verdict: [ALLOWED]

Verdict: allowed
EOF

DIFF=$(diff -Nru  <(cilium policy trace -s id.foo -d id.bar) <(echo "$EXPECTED_POLICY")) || true
if [[ "$DIFF" != "" ]]; then
	abort "$DIFF"
fi

BAR_ID=$(cilium endpoint list | grep id.bar | awk '{ print $1}')
FOO_SEC_ID=$(cilium endpoint list | grep id.foo | awk '{ print $2}')

EXPECTED_CONSUMER="[\n  1,\n  $FOO_SEC_ID\n]"
DIFF=$(diff -Nru  <(cilium endpoint get $BAR_ID | jq '.policy | .["allowed-consumers"]') <(echo -e "$EXPECTED_CONSUMER")) || true
if [[ "$DIFF" != "" ]]; then
	abort "$DIFF"
fi

cilium policy delete
