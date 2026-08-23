namespace :oydid do

    # Setzt sub_hash fuer alle REVOKE-Eintraege und korrigiert oyd_hash dort,
    # wo bisher die sub-entry-hash gespeichert war.
    #
    # Standardmaessig ein Bericht ohne Aenderung. Schreiben mit APPLY=1.
    desc "REVOKE-Log-Hashes inventarisieren und korrigieren (APPLY=1 zum Schreiben)"
    task backfill_log_hashes: :environment do
        ActiveRecord::Base.logger = nil
        apply = ENV["APPLY"].to_s == "1"
        puts apply ? "== MODUS: schreiben" : "== MODUS: Bericht (APPLY=1 zum Schreiben)"

        term_docs = Set.new
        Log.where("item LIKE ?", '%"op":0%').pluck(:item).each do |raw|
            e = JSON.parse(raw) rescue next
            next if e["op"].to_i != 0
            term_docs << e["doc"].to_s.split(LOCATION_PREFIX).first
        end
        puts "TERMINATE-Eintraege mit doc-Verweis: #{term_docs.size}"

        rows = []
        Log.where("item LIKE ?", '%"op":1%').find_each do |log|
            e = JSON.parse(log.item) rescue next
            next if e["op"].to_i != 1
            entry, sub = Log.hashes_for(e, LOG_HASH_OPTIONS)
            kat = if    log.oyd_hash == entry then :entry_gespeichert
                  elsif log.oyd_hash == sub   then :sub_gespeichert
                  elsif term_docs.include?(log.oyd_hash) then :legacy_referenziert
                  else  :legacy_unbekannt
                  end
            rows << { log: log, entry: entry, sub: sub, kat: kat }
        end

        stat = Hash.new(0)
        rows.each { |r| stat[r[:kat]] += 1 }
        puts
        puts "REVOKE-Eintraege gesamt: #{rows.size}"
        stat.sort_by { |_, v| -v }.each { |k, v| puts format("   %-22s %d", k, v) }

        # Nur die :sub_gespeichert-Zeilen bekommen ein neues oyd_hash - und nur,
        # wenn die Ziel-Hash nicht schon von einer anderen Zeile belegt ist
        # (index_logs_on_oyd_hash ist UNIQUE).
        belegt = Log.where(oyd_hash: rows.map { |r| r[:entry] }.compact)
                    .pluck(:oyd_hash, :id).to_h
        kollision = []
        rows.each do |r|
            next if r[:kat] != :sub_gespeichert
            other = belegt[r[:entry]]
            kollision << [r[:log].id, other, r[:entry]] if other && other != r[:log].id
        end

        puts
        puts "Kollisionen (derselbe Record doppelt gespeichert): #{kollision.size}"
        kollision.first(10).each { |mine, other, h|
            puts "   Log ##{mine} <-> ##{other}   #{h}" }
        puts "   -> diese Zeilen bleiben unangetastet und brauchen eine eigene" \
             " Entscheidung" if kollision.any?

        next unless apply

        kollidiert = kollision.map(&:first).to_set
        geaendert = 0
        ActiveRecord::Base.transaction do
            rows.each do |r|
                next if kollidiert.include?(r[:log].id)
                attrs = {}
                case r[:kat]
                when :sub_gespeichert
                    attrs[:oyd_hash] = r[:entry]
                    attrs[:sub_hash] = r[:log].oyd_hash
                when :entry_gespeichert
                    attrs[:sub_hash] = r[:sub]
                when :legacy_referenziert
                    # oyd_hash IST hier die sub-entry-hash nach damaligen Regeln
                    attrs[:sub_hash] = r[:log].oyd_hash
                when :legacy_unbekannt
                    # oyd_hash nicht anfassen; sub_hash als zusaetzlichen
                    # Schluessel setzen, schadet nicht wenn er ins Leere zeigt
                    attrs[:sub_hash] = r[:sub]
                end
                next if attrs.empty?
                next if attrs.all? { |k, v| r[:log].send(k) == v }
                r[:log].update_columns(attrs)
                geaendert += 1
            end
        end
        puts
        puts "geaenderte Zeilen: #{geaendert}"
    end
end
