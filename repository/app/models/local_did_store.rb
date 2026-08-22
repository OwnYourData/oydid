# Adapter that lets the oydid gem resolve DID documents and logs from the local
# database instead of fetching them over HTTP.
#
# The gem calls #get(doc_hash) in retrieve_document_raw when it receives this
# object via options[:local_store]. Resolution happens per hash, which matters
# for Oydid.dag_update: it walks several different documents along an update
# chain, so a single options[:local_doc] cannot serve all of them.
#
# Returns the same shape the remote /doc_raw endpoint returns:
#   {"doc" => <did document>, "log" => [<log entries>]}
# or nil when the hash is unknown here, in which case the gem falls back to its
# regular lookup.
class LocalDidStore
    include ApplicationHelper

    def get(doc_hash)
        did_hash = doc_hash.to_s.delete_prefix("did:oyd:")
        did_hash = did_hash.split(LOCATION_PREFIX).first.to_s
        did_hash = did_hash.split(CGI.escape(LOCATION_PREFIX)).first.to_s
        return nil if did_hash == ""

        _did, doc = local_retrieve_document(did_hash)
        return nil if doc.nil?

        {"doc" => doc, "log" => local_retrieve_log(did_hash)}
    end
end
