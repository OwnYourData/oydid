#!/usr/bin/env bash

OYDIDCMD='../oydid.rb'
# OYDIDCMD='oydid'

# install current version
# sh -c "curl -fsSL https://raw.githubusercontent.com/OwnYourData/did-cmd/main/install.sh | sh"

# clean up
$OYDIDCMD delete did:oyd:zQmPoNSNpZAae4qDsr2amNj6YKfGT1YmKAHzEGbF6VqAq5Q --doc-key c1/private_key.b58 --rev-key c1/revocation_key.b58 --silent
$OYDIDCMD delete zQmZfyr7pGwQPzXbt664MdfmNwyG7CMZErHN724x8tKvBhP --doc-key c1/private_key.b58 --rev-key c1/revocation_key.b58 --silent
$OYDIDCMD delete did:oyd:zQmTyeNTS3p9GrVCut7QUg925aiGKJ8YxpD2LNuk8em69UX --doc-pwd pwd1 --rev-pwd pwd2 --silent
$OYDIDCMD delete did:oyd:zQmXzfYoMDRkwcSZaXzVGz6XqELaDhwyZCkzjGdcwa9vpVd --doc-pwd pwd1 --rev-pwd pwd2 --silent
$OYDIDCMD delete "did:oyd:zQmfEPuXTJ9ANQgLFu96DoTb2n5wvCD1sP9kTRSj929G5Sn@https://did2.data-container.net" --doc-pwd pwd1 --rev-pwd pwd2 --silent
$OYDIDCMD delete "did:oyd:zQmX2Rme63uEj5YCnMR4TBt7GJRwVEqTEPyxk6Zh1CS7Lzk@https://did2.data-container.net" --doc-pwd pwd1 --rev-pwd pwd2 --silent


# test creating local DID Document
echo '{"hello": "world"}' | $OYDIDCMD create -l local --doc-key c1/private_key.b58 --rev-key c1/revocation_key.b58 --ts 1610839947
if ! cmp -s zQmUNiQciw.doc c1/did.doc ; then
	echo "creating failed"
	rm zQmUNiQciw*
	exit 1
fi
rm zQmUNiQciw*

# test creating invalid DID Document
retval=`echo '{' | $OYDIDCMD create -l local --doc-key c1/private_key.b58 --rev-key c1/revocation_key.b58`
if [ "$retval" == "Error: empty or invalid payload" ]; then
	echo "invalid input handled"
else
	echo "processing invalid input failed"
	exit 1
fi

# test creating public DID Document
echo '{"hello": "world2"}' | $OYDIDCMD create --doc-key c1/private_key.b58 --rev-key c1/revocation_key.b58 --ts 1610839947
$OYDIDCMD read did:oyd:zQmPoNSNpZAae4qDsr2amNj6YKfGT1YmKAHzEGbF6VqAq5Q > tmp.doc
if ! cmp -s tmp.doc c1/zQmPoNSNpZ.doc ; then
	echo "reading from public failed"
	rm tmp.doc
	exit 1
fi
$OYDIDCMD read --w3c-did did:oyd:zQmPoNSNpZAae4qDsr2amNj6YKfGT1YmKAHzEGbF6VqAq5Q > tmp.doc
if ! cmp -s tmp.doc c1/w3c-did.doc ; then
	echo "converting to W3C DID format failed"
	rm tmp.doc
	exit 1
else
	echo "W3C formatting valid"
fi
rm tmp.doc

# test updating DID Document
echo '{"hello": "world3"}' | $OYDIDCMD update did:oyd:zQmPoNSNpZAae4qDsr2amNj6YKfGT1YmKAHzEGbF6VqAq5Q --json-output --doc-key c1/private_key.b58 --rev-key c1/revocation_key.b58 --ts 1610839948 > tmp.doc
if ! cmp -s tmp.doc c1/json-did.doc ; then
	echo "output in JSON format failed"
	rm tmp.doc
	exit 1
else
	echo "JSON formatting for update valid"
fi
rm tmp.doc
$OYDIDCMD read did:oyd:zQmPoNSNpZAae4qDsr2amNj6YKfGT1YmKAHzEGbF6VqAq5Q > tmp.doc
if ! cmp -s tmp.doc c1/zQmZfyr7pGwQP.doc ; then
	echo "updating public failed"
	rm tmp.doc
	exit 1
fi
rm tmp.doc

# test creating public DID Document with password
echo '{"hello": "world4"}' | $OYDIDCMD create --doc-pwd pwd1 --rev-pwd pwd2 --ts 1610839947
$OYDIDCMD read did:oyd:zQmTyeNTS3p9GrVCut7QUg925aiGKJ8YxpD2LNuk8em69UX > tmp.doc
if ! cmp -s tmp.doc c1/pwd.doc ; then
	echo "creating with password failed"
	rm tmp.doc
	exit 1
fi
rm tmp.doc

# test updating DID Document with password
echo '{"hello": "world5"}' | $OYDIDCMD update did:oyd:zQmTyeNTS3p9GrVCut7QUg925aiGKJ8YxpD2LNuk8em69UX --doc-pwd pwd1 --rev-pwd pwd2 --ts 1610839948
$OYDIDCMD read did:oyd:zQmTyeNTS3p9GrVCut7QUg925aiGKJ8YxpD2LNuk8em69UX > tmp.doc
if ! cmp -s tmp.doc c1/pwd2.doc ; then
	echo "updating with password failed"
	rm tmp.doc
	exit 1
fi
rm tmp.doc

# test revoking DID
$OYDIDCMD revoke did:oyd:zQmTyeNTS3p9GrVCut7QUg925aiGKJ8YxpD2LNuk8em69UX --doc-pwd pwd1 --rev-pwd pwd2
retval=`$OYDIDCMD read did:oyd:zQmTyeNTS3p9GrVCut7QUg925aiGKJ8YxpD2LNuk8em69UX`
if [ "$retval" != "Error: cannot resolve DID" ]; then
	echo "revoking DID failed"
	rm tmp.doc
	exit 1
fi
$OYDIDCMD delete did:oyd:zQmTyeNTS3p9GrVCut7QUg925aiGKJ8YxpD2LNuk8em69UX --doc-pwd pwd1 --rev-pwd pwd2

# test writing to non-default location
echo '{"hello": "world6"}' | $OYDIDCMD create -l https://did2.data-container.net --doc-pwd pwd1 --rev-pwd pwd2 --ts 1610839947
$OYDIDCMD read "did:oyd:zQmfEPuXTJ9ANQgLFu96DoTb2n5wvCD1sP9kTRSj929G5Sn@https://did2.data-container.net" > tmp.doc
if ! cmp -s tmp.doc c1/did2.doc ; then
	echo "writing to non-default location failed"
	rm tmp.doc
	exit 1
fi
rm tmp.doc
$OYDIDCMD delete "did:oyd:zQmfEPuXTJ9ANQgLFu96DoTb2n5wvCD1sP9kTRSj929G5Sn@https://did2.data-container.net" --doc-pwd pwd1 --rev-pwd pwd2

# test clone
$OYDIDCMD clone did:oyd:zQmZfyr7pGwQPzXbt664MdfmNwyG7CMZErHN724x8tKvBhP --doc-pwd pwd1 --rev-pwd pwd2 --ts 1610839948 -l https://did2.data-container.net
$OYDIDCMD read "did:oyd:zQmX2Rme63uEj5YCnMR4TBt7GJRwVEqTEPyxk6Zh1CS7Lzk@https://did2.data-container.net" > tmp.doc
if ! cmp -s tmp.doc c1/did_clone.doc ; then
	echo "cloning failed"
	rm tmp.doc
	exit 1
fi
rm tmp.doc


# test public OYDID resolver
curl -s -k https://oydid-resolver.data-container.net/1.0/identifiers/did:oyd:zQmZ8DEGQtJcpoQDMKYJkTiQn9dQLM2QzvmDQXuj8vCfvdj | jq ".didDocument" > tmp.doc
if ! cmp -s tmp.doc c1/uni1.doc ; then
	echo "resolving with public OYDID resolver failed"
	rm tmp.doc
	exit 1
fi

curl -s -k https://oydid-resolver.data-container.net/1.0/identifiers/did:oyd:zQmX2Rme63uEj5YCnMR4TBt7GJRwVEqTEPyxk6Zh1CS7Lzk@https://did2.data-container.net | jq ".didDocument" > tmp.doc
if ! cmp -s tmp.doc c1/uni2.doc ; then
	echo "resolving non-default location with uniresolver failed"
	rm tmp.doc
	exit 1
fi
rm tmp.doc
echo "testing public OYDID resolver successful"

# test Uniresolver
curl -s https://dev.uniresolver.io/1.0/identifiers/did:oyd:zQmZ8DEGQtJcpoQDMKYJkTiQn9dQLM2QzvmDQXuj8vCfvdj | jq ".didDocument" > tmp.doc
if ! cmp -s tmp.doc c1/uni1.doc ; then
	echo "resolving with uniresolver failed"
	rm tmp.doc
	exit 1
fi

curl -s https://dev.uniresolver.io/1.0/identifiers/did:oyd:zQmX2Rme63uEj5YCnMR4TBt7GJRwVEqTEPyxk6Zh1CS7Lzk@https://did2.data-container.net | jq ".didDocument" > tmp.doc
if ! cmp -s tmp.doc c1/uni2.doc ; then
	echo "resolving non-default location with uniresolver failed"
	rm tmp.doc
	exit 1
fi
echo "testing Uniresolver successful"
rm tmp.doc


# $OYDIDCMD delete did:oyd:zQmPoNSNpZAae4qDsr2amNj6YKfGT1YmKAHzEGbF6VqAq5Q --doc-key c1/private_key.b58 --rev-key c1/revocation_key.b58
# $OYDIDCMD delete zQmZfyr7pGwQPzXbt664MdfmNwyG7CMZErHN724x8tKvBhP --doc-key c1/private_key.b58 --rev-key c1/revocation_key.b58
# $OYDIDCMD delete "did:oyd:zQmX2Rme63uEj5YCnMR4TBt7GJRwVEqTEPyxk6Zh1CS7Lzk@https://did2.data-container.net" --doc-pwd pwd1 --rev-pwd pwd2 

echo "tests finished successfully"
