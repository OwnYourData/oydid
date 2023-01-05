#!/usr/bin/env bash

OYDIDCMD='../oydid.rb'
# OYDIDCMD='oydid'

# install current version
# sh -c "curl -fsSL https://raw.githubusercontent.com/OwnYourData/did-cmd/main/install.sh | sh"

CLEAN=true
while [ $# -gt 0 ]; do
    case "$1" in
        --no-clean*)
            CLEAN=false
            ;;
    esac
    shift
done
if $CLEAN; then
	# clean up ------------------------
	# world2: creating public DID Document
	$OYDIDCMD delete did:oyd:zQmZcUx2V9eScpAwaTnQ7Zcx8cXd2nBrJiSwyZMh7BTXKgz --doc-key c1/private_key.enc --rev-key c1/revocation_key.enc --silent
	# world3: updating DID Document
	$OYDIDCMD delete did:oyd:zQmbehq1983ipEys6N1uAk1vYhMGtrU1oq7QWGiesZXFi3h --doc-key c1/private_key.enc --rev-key c1/revocation_key.enc --silent
	# world4: creating public DID Document with password
	$OYDIDCMD delete did:oyd:zQmeMnYBBYvddAdgH6Ape2L4FzRty3y69grDZcQd5kR2tQH --doc-pwd pwd1 --rev-pwd pwd2 --silent
	# world5: updating DID Document with same password
	$OYDIDCMD delete did:oyd:zQmf6qRANG6XeKKcrbJ1tz2PZem5pndAG5as99dFaPaYvpi --doc-pwd pwd1 --rev-pwd pwd2 --silent
	# world6: updating DID Document with different password
	$OYDIDCMD delete did:oyd:zQme7H3X9CheEE9ftWAjDiEsBbomFVmijHsWqP9dn3KsUsd --doc-pwd pwd3 --rev-pwd pwd4 --silent
	# world7: writing to non-default location
	$OYDIDCMD delete "did:oyd:zQmfNbBWMdLf32dTyPEDZd61t8Uw4t6czfPj1K9DyuXLqVF@https://did2.data-container.net" --doc-pwd pwd1 --rev-pwd pwd2 --silent
	# clone world3
	$OYDIDCMD delete "did:oyd:zQmNnWFo7945khmUxRoUksdQAhzEAgkfBS8Hv6xCo2RsjtS@https://did2.data-container.net" --doc-pwd pwd1 --rev-pwd pwd2 --silent
fi

# test handling local DID Document
echo '{"hello": "world"}' | $OYDIDCMD create -l local --doc-key c1/private_key.enc --rev-key c1/revocation_key.enc -z 1610839947
if ! cmp -s zQmPfjgZhN.doc c1/did.doc ; then
	echo "creating local failed"
	rm zQmPfjgZhN*
	exit 1
fi
$OYDIDCMD read did:oyd:zQmPfjgZhNsHf9ZyM9VnNu6F8sT4xQnHNXKEwbDK1uXyVfy@local > tmp.doc
if ! cmp -s tmp.doc c1/did_local.doc ; then
	echo "reading local failed"
	# rm zQmPfjgZhN*
	# rm tmp.doc
	exit 1
fi
rm tmp.doc
rm zQmPfjgZhN*

# test creating invalid DID Document
retval=`echo '{' | $OYDIDCMD create -l local --doc-key c1/private_key.enc --rev-key c1/revocation_key.enc`
if [ "$retval" == "Error: empty or invalid payload" ]; then
	echo "invalid input handled"
else
	echo "processing invalid input failed"
	exit 1
fi

# test creating public DID Document
echo '{"hello": "world2"}' | $OYDIDCMD create --doc-key c1/private_key.enc --rev-key c1/revocation_key.enc -z 1610839947
$OYDIDCMD read did:oyd:zQmZcUx2V9eScpAwaTnQ7Zcx8cXd2nBrJiSwyZMh7BTXKgz > tmp.doc
if ! cmp -s tmp.doc c1/zQmZcUx2V9.doc ; then
	echo "reading from public failed"
	rm tmp.doc
	exit 1
fi
$OYDIDCMD read --w3c-did did:oyd:zQmZcUx2V9eScpAwaTnQ7Zcx8cXd2nBrJiSwyZMh7BTXKgz > tmp.doc
if ! cmp -s tmp.doc c1/w3c-did.doc ; then
	echo "converting to W3C DID format failed"
	rm tmp.doc
	exit 1
else
	echo "W3C formatting valid"
fi
rm tmp.doc

# test updating DID Document
echo '{"hello": "world3"}' | $OYDIDCMD update did:oyd:zQmZcUx2V9eScpAwaTnQ7Zcx8cXd2nBrJiSwyZMh7BTXKgz --json-output --doc-key c1/private_key.enc --rev-key c1/revocation_key.enc -z 1610839948 > tmp.doc
if ! cmp -s tmp.doc c1/json-did.doc ; then
	echo "output in JSON format failed"
	rm tmp.doc
	exit 1
else
	echo "JSON formatting for update valid"
fi
rm tmp.doc
$OYDIDCMD read did:oyd:zQmbehq1983ipEys6N1uAk1vYhMGtrU1oq7QWGiesZXFi3h > tmp.doc
if ! cmp -s tmp.doc c1/zQmbehq1983ip.doc ; then
	echo "updating public failed"
	rm tmp.doc
	exit 1
fi
rm tmp.doc

# test creating public DID Document with password
echo '{"hello": "world4"}' | $OYDIDCMD create --doc-pwd pwd1 --rev-pwd pwd2 -z 1610839947
$OYDIDCMD read did:oyd:zQmeMnYBBYvddAdgH6Ape2L4FzRty3y69grDZcQd5kR2tQH > tmp.doc
if ! cmp -s tmp.doc c1/pwd.doc ; then
	echo "creating with password failed"
	rm tmp.doc
	exit 1
fi
rm tmp.doc

# test updating DID Document with password
echo '{"hello": "world5"}' | $OYDIDCMD update did:oyd:zQmeMnYBBYvddAdgH6Ape2L4FzRty3y69grDZcQd5kR2tQH --doc-pwd pwd1 --rev-pwd pwd2 -z 1610839948
$OYDIDCMD read did:oyd:zQmeMnYBBYvddAdgH6Ape2L4FzRty3y69grDZcQd5kR2tQH > tmp.doc
if ! cmp -s tmp.doc c1/pwd2.doc ; then
	echo "updating with password failed"
	rm tmp.doc
	exit 1
fi
rm tmp.doc

# test verification flag
$OYDIDCMD read --show-verification did:oyd:zQmeMnYBBYvddAdgH6Ape2L4FzRty3y69grDZcQd5kR2tQH > tmp.doc
if ! cmp -s tmp.doc c1/verification.doc ; then
	echo "show-verification failed"
	rm tmp.doc
	exit 1
fi
rm tmp.doc

# test key rotation
echo '{"hello": "world6"}' | $OYDIDCMD update did:oyd:zQmf6qRANG6XeKKcrbJ1tz2PZem5pndAG5as99dFaPaYvpi --doc-pwd pwd3 --rev-pwd pwd4 -z 1610839949
$OYDIDCMD read --show-verification did:oyd:zQmeMnYBBYvddAdgH6Ape2L4FzRty3y69grDZcQd5kR2tQH > tmp.doc
if ! cmp -s tmp.doc c1/verification2.doc ; then
	echo "key rotation failed"
	rm tmp.doc
	exit 1
fi
rm tmp.doc

# test revoking DID
$OYDIDCMD revoke did:oyd:zQme7H3X9CheEE9ftWAjDiEsBbomFVmijHsWqP9dn3KsUsd --doc-pwd pwd3 --rev-pwd pwd4
retval=`$OYDIDCMD read did:oyd:zQmeMnYBBYvddAdgH6Ape2L4FzRty3y69grDZcQd5kR2tQH`
if [ "$retval" != "Error: cannot resolve DID (on reading DID)" ]; then
	echo "revoking DID failed"
	rm tmp.doc
	exit 1
fi
# $OYDIDCMD delete did:oyd:zQmeMnYBBYvddAdgH6Ape2L4FzRty3y69grDZcQd5kR2tQH --doc-pwd pwd1 --rev-pwd pwd2

# test writing to non-default location
echo '{"hello": "world7"}' | $OYDIDCMD create -l https://did2.data-container.net --doc-pwd pwd1 --rev-pwd pwd2 -z 1610839947
$OYDIDCMD read "did:oyd:zQmfNbBWMdLf32dTyPEDZd61t8Uw4t6czfPj1K9DyuXLqVF@https://did2.data-container.net" > tmp.doc
if ! cmp -s tmp.doc c1/did2.doc ; then
	echo "writing to non-default location failed"
	rm tmp.doc
	exit 1
fi
rm tmp.doc
$OYDIDCMD read "did:oyd:zQmfNbBWMdLf32dTyPEDZd61t8Uw4t6czfPj1K9DyuXLqVF@did2.data-container.net" > tmp.doc
if ! cmp -s tmp.doc c1/did2.doc ; then
	echo "reading from non-default location with omitting protocol failed"
	rm tmp.doc
	exit 1
fi
rm tmp.doc
$OYDIDCMD delete "did:oyd:zQmfNbBWMdLf32dTyPEDZd61t8Uw4t6czfPj1K9DyuXLqVF@https://did2.data-container.net" --doc-pwd pwd1 --rev-pwd pwd2

# test clone
$OYDIDCMD clone did:oyd:zQmbehq1983ipEys6N1uAk1vYhMGtrU1oq7QWGiesZXFi3h --doc-pwd pwd1 --rev-pwd pwd2 -z 1610839948 -l https://did2.data-container.net
$OYDIDCMD read "did:oyd:zQmNnWFo7945khmUxRoUksdQAhzEAgkfBS8Hv6xCo2RsjtS@https://did2.data-container.net" > tmp.doc
if ! cmp -s tmp.doc c1/did_clone.doc ; then
	echo "cloning failed"
	rm tmp.doc
	exit 1
fi
rm tmp.doc

# test to/fromW3C
cat c1/oydid.did | $OYDIDCMD toW3C > tmp.doc
if ! cmp -s tmp.doc c1/w3c.did ; then
	echo "converting toW3C failed"
	rm tmp.doc
	exit 1
fi
rm tmp.doc

cat c1/w3c.did | $OYDIDCMD fromW3C > tmp.doc
if ! cmp -s tmp.doc c1/oydid.did ; then
	echo "converting fromW3C failed"
	rm tmp.doc
	exit 1
fi
rm tmp.doc
echo "converting between OYDID and W3C successful"


# test public OYDID resolver
curl -s -k https://oydid-resolver.data-container.net/1.0/identifiers/did:oyd:zQmaBZTghndXTgxNwfbdpVLWdFf6faYE4oeuN2zzXdQt1kh | jq ".didDocument" > tmp.doc
if ! cmp -s tmp.doc c1/uni1_new.doc ; then
	echo "resolving DID with public OYDID resolver failed"
	rm tmp.doc
	exit 1
fi
rm tmp.doc

curl -s -k https://oydid-resolver.data-container.net/1.0/identifiers/did:oyd:zQmNauTUUdkpi5TcrTZ2524SKM8dJAzuuw4xfW13iHrtY1W@did2.data-container.net | jq ".didDocument" > tmp.doc
if ! cmp -s tmp.doc c1/uni2_new.doc ; then
	echo "resolving DID at non-default location with OYDID resolver failed"
	rm tmp.doc
	exit 1
fi
rm tmp.doc

# curl -s -k https://oydid-resolver.data-container.net/1.0/identifiers/did:oyd:zQmZ8DEGQtJcpoQDMKYJkTiQn9dQLM2QzvmDQXuj8vCfvdj | jq ".didDocument" > tmp.doc
# if ! cmp -s tmp.doc c1/uni1.doc ; then
# 	echo "resolving legacy DID with public OYDID resolver failed"
# 	rm tmp.doc
# 	exit 1
# fi
# rm tmp.doc

# curl -s -k https://oydid-resolver.data-container.net/1.0/identifiers/did:oyd:zQmbbgEXLq96rHSRfydhsSQ9HCs6p7Cf4R98Qn7NdXig1Vk%40https%3A%2F%2Fdid2.data-container.net | jq ".didDocument" > tmp.doc
# if ! cmp -s tmp.doc c1/uni2.doc ; then
# 	echo "resolving legacy DID at non-default location with OYDID resolver failed"
# 	rm tmp.doc
# 	exit 1
# fi
# rm tmp.doc

echo "testing public OYDID resolver successful"

# test Uniresolver
curl -s https://dev.uniresolver.io/1.0/identifiers/did:oyd:zQmaBZTghndXTgxNwfbdpVLWdFf6faYE4oeuN2zzXdQt1kh | jq ".didDocument" > tmp.doc
if ! cmp -s tmp.doc c1/uni1_new.doc ; then
	echo "resolving with uniresolver failed"
	rm tmp.doc
	exit 1
fi
rm tmp.doc

curl -s https://dev.uniresolver.io/1.0/identifiers/did:oyd:zQmNauTUUdkpi5TcrTZ2524SKM8dJAzuuw4xfW13iHrtY1W%40did2.data-container.net | jq ".didDocument" > tmp.doc
if ! cmp -s tmp.doc c1/uni2_new.doc ; then
	echo "resolving non-default location with uniresolver failed"
	rm tmp.doc
	exit 1
fi
rm tmp.doc

# curl -s https://dev.uniresolver.io/1.0/identifiers/did:oyd:zQmZ8DEGQtJcpoQDMKYJkTiQn9dQLM2QzvmDQXuj8vCfvdj | jq ".didDocument" > tmp.doc
# if ! cmp -s tmp.doc c1/uni1.doc ; then
# 	echo "resolving legacy DID with uniresolver failed"
# 	rm tmp.doc
# 	exit 1
# fi
# rm tmp.doc

# curl -s https://dev.uniresolver.io/1.0/identifiers/did:oyd:zQmbbgEXLq96rHSRfydhsSQ9HCs6p7Cf4R98Qn7NdXig1Vk%40https%3A%2F%2Fdid2.data-container.net | jq ".didDocument" > tmp.doc
# if ! cmp -s tmp.doc c1/uni2.doc ; then
# 	echo "resolving legacy DID at non-default location with uniresolver failed"
# 	rm tmp.doc
# 	exit 1
# fi
echo "testing Uniresolver successful"
rm zQm*


echo "tests finished successfully"
