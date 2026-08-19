# Be sure to restart your server when you modify this file.

# Configure sensitive parameters which will be filtered from the log file.
#
# This service accepts OYDID key material as request parameters, and Rails
# writes unfiltered parameters into the request log verbatim. Filtering only
# :password was not enough: dockey/revkey (repository API), doc_key/rev_key
# (uniregistrar "secret" object) and the CLI's pwd/enc variants all ended up
# in log files that were committed to a public repository.
#
# Rails matches these as substrings, so :key covers dockey, revkey, doc_key,
# rev_key and pubkey, and :pwd covers doc_pwd, rev_pwd and the old_* variants.
# The *_enc names are listed in full so that "encoding" is not caught too.
Rails.application.config.filter_parameters += [
  :password, :secret, :token, :crypt, :salt,
  :key, :pwd,
  :doc_enc, :rev_enc, :old_doc_enc, :old_rev_enc,
]
