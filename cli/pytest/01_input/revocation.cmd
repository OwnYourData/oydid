did=`echo '' | oydid create --doc-pwd pwd1 --rev-pwd pwd2 -s --json-output | jq -r '.did'` && oydid revoke --doc-pwd pwd1 --rev-pwd pwd2 -s $did > /dev/null 2>&1 && oydid logs $did | jq -r '. | length'