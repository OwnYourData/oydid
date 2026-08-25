namespace :oydid do

    # Sammel-Schluessel, die bewusst NICHT nachgetragen werden. An ihnen haengen
    # tausende Experiment-DIDs; der Shortcut did:oyd:{public-key} haette dort
    # keine Aussage, und der CREATE-Guardrail wuerde sich auf einen Bestand
    # ausweiten, dessen Herkunft ungeklaert ist. Entscheidung Christoph,
    # 2026-08-25. Zeilen dieser Schluessel bleiben auf public_key = NULL.
    BACKFILL_SKIP_KEYS = [
        "z6Mv7ZGSozC9MLt4j9neeqCo47rDe6qvfHB7RA8hEGnX4aFG"
    ].freeze

    # Traegt public_key fuer Altzeilen nach.
    #
    # Die Spalte wird nur beim erstmaligen Anlegen einer DID-Zeile gesetzt
    # (ApplicationHelper#local_store_did) und kam erst mit der Migration im
    # November 2022 dazu. Aeltere Zeilen haben sie nie bekommen, und ein
    # erneutes Publizieren derselben DID fuellt sie auch nicht nach - der
    # Schreibpfad legt nur an, wenn die Zeile noch fehlt. Fuer diese DIDs
    # laeuft der Shortcut did:oyd:{public-key} deshalb in einen 404.
    #
    # Standardmaessig ein Bericht ohne Aenderung. Schreiben mit APPLY=1.
    desc "public_key fuer Altzeilen aus dem Dokument nachtragen (APPLY=1 zum Schreiben)"
    task backfill_public_keys: :environment do
        ActiveRecord::Base.logger = nil
        apply = ENV["APPLY"].to_s == "1"
        puts apply ? "== MODUS: schreiben" : "== MODUS: Bericht (APPLY=1 zum Schreiben)"
        BACKFILL_SKIP_KEYS.each { |k| puts "ausgenommener Sammel-Schluessel: #{k}" }

        offen = Did.where(public_key: nil)
        puts "Zeilen ohne public_key: #{offen.count} von #{Did.count}"

        rows = []
        stat = Hash.new(0)
        offen.find_each do |did|
            doc = JSON.parse(did.doc.to_s) rescue nil
            if !doc.is_a?(Hash)
                stat[:doc_unlesbar] += 1
                next
            end
            key = doc["key"].to_s.split(":").first.to_s
            if key.empty?
                stat[:key_fehlt] += 1
                next
            end
            if BACKFILL_SKIP_KEYS.include?(key)
                stat[:ausgenommen] += 1
                next
            end
            stat[:key_gefunden] += 1
            rows << [did, key]
        end

        puts
        stat.sort_by { |_, v| -v }.each { |k, v| puts format("   %-16s %d", k, v) }

        # Was nach dem Nachtragen an Mehrfachbelegungen sichtbar wird. Die
        # Aufloesung ist dadurch nicht mehrdeutig - Did.find_by_public_key_active
        # liefert die juengste nicht widerrufene Version - aber der Umfang
        # gehoert vor die Entscheidung, nicht dahinter.
        neu = Hash.new(0)
        rows.each { |(_, key)| neu[key] += 1 }
        bestehend = Hash.new(0)
        neu.keys.each_slice(1000) do |slice|
            Did.where(public_key: slice).group(:public_key).count.each { |k, v| bestehend[k] = v }
        end
        mehrfach = neu.map { |key, n| [key, n + bestehend[key]] }
                      .select { |(_, n)| n > 1 }
                      .sort_by { |(_, n)| -n }

        puts
        puts "Schluessel mit danach mehr als einer DID: #{mehrfach.size}" \
             " (betroffene Zeilen: #{mehrfach.sum { |(_, n)| n }})"
        # revoked? kostet zwei Log-Abfragen pro Zeile - deshalb nur fuer die
        # groessten Gruppen, die restlichen Zahlen stehen oben.
        mehrfach.first(10).each do |(key, n)|
            aktiv = Did.where(public_key: key).to_a.count { |d| !d.revoked? }
            aktiv += rows.count { |(did, k)| k == key && !did.revoked? }
            puts format("   %-50s %d DIDs, davon aktiv %d", key, n, aktiv)
        end

        next unless apply

        geaendert = 0
        rows.each_slice(500) do |slice|
            ActiveRecord::Base.transaction do
                slice.each do |(did, key)|
                    next unless did.public_key.nil?
                    did.update_columns(public_key: key)
                    geaendert += 1
                end
            end
        end
        puts
        puts "geaenderte Zeilen: #{geaendert}"
    end
end
