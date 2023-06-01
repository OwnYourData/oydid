did=`echo '' | oydid create --doc-pwd pwd1 --rev-pwd pwd2 -s --json-output | jq -r '.did'` && \
doc_log=`oydid delegate --doc-pwd pwd3 $did --json-output | jq -r '.log'` && \
rev_log=`oydid delegate --rev-pwd pwd4 $did --json-output | jq -r '.log'` && \
echo "[\"$doc_log\", \"$rev_log\"]" | oydid confirm --doc-pwd pwd5 --rev-pwd pwd5 --old-doc-pwd pwd1 --old-rev-pwd pwd2 -s $did > /dev/null 2>&1 && \
oydid revoke --doc-pwd pwd3 --rev-pwd pwd4 $did > /dev/null 2>&1 && \
oydid logs $did | jq 'length'