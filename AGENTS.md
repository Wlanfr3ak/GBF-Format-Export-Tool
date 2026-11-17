# AGENTS.md — Projektregeln für GBF-Extract

## Projekt

`gbf_extract.py` — Entschlüsselt und extrahiert Geutebrück **G-Core Backup Files**
(`.gbf`). Entstanden durch Reverse Engineering einer exportierten
Videosicherung (G-Core 7.0.0.60). Ausgabe: rohe H.264-Streams
(`.264`), abspielbare MP4-Container, Export-Metadaten (XML), Event-Logs
und ein druckbarer DIN-A4-PDF-Bericht pro Export.

## Harte Regeln

1. **Jede Änderung am Code erfordert eine Versionsänderung.**
   `__version__` in `src/gbf_extract.py` hochzählen (Semantic Versioning:
   MAJOR.MINOR.PATCH).
2. **Die Release-Exe muss die Versionsnummer im Dateinamen tragen:**
   `dist/GBF-Extract_v<VERSION>.exe` (wird von `build.py` automatisch erzeugt).
3. **Jede Version bekommt einen ausführlichen `CHANGELOG.md`-Eintrag**
   (Was, Warum, betroffene Dateiformat-Bereiche).
4. **`README.md` mitpflegen** — jeder Reverse-Engineering- oder
   Implementierungsschritt wird dort dokumentiert.
5. **Passwörter niemals hartkodieren oder committen.** Passwort kommt per
   GUI-Eingabefeld, `-p`, `--password-file` oder interaktiver Eingabe
   (getpass, kein Echo).
6. **Original-GBF niemals verändern.** Das Programm arbeitet ausschließlich
   lesend; alle Ausgaben gehen in ein separates Ausgabeverzeichnis.
7. **Offline-Ziel:** die gebaute `.exe` muss auf einem frischen Windows 11
   ohne Internet und ohne installiertes Python laufen (PyInstaller `--onefile`,
   alle Abhängigkeiten gebündelt).
8. **Dual-Mode:** Start ohne Argumente ⇒ GUI (Tkinter + tkinterdnd2);
   mit Argumenten ⇒ CLI. Beide Modi müssen in der Exe funktionieren.
   Tcl/Tk-Data aus dem Python-Prefix wird von `build.py` in
   `_tcl_data`/`_tk_data` ins Bundle gelegt (PyInstaller-Hook-Konvention).
9. **Export-Ordner = Dateiname:** Der Export-Ordner heißt immer wie die
   `.gbf` ohne Endung (`<ziel>/<dateiname>/`); `-o`/Zielordner ist das
   Elternverzeichnis (Default: Ordner der `.gbf`).
10. **PDF-Bericht:** Pro Export wird `<dateiname>_report.pdf` (DIN A4)
    erzeugt — Quelldatei-Fakten inkl. SHA-256, ExportInfo-Metadaten,
    Standbild + Statistiken je Kamera, Events, Roh-XML. Abschaltbar per
    `--no-report` / GUI-Checkbox.
11. **Doku anonymisiert:** Keine echten Kunden-, Kamera- oder Dateinamen
    in README/CHANGELOG/AGENTS — neutrale Platzhalter verwenden.

## GitHub-Release-Prozess

1. **Jede Version bekommt ein GitHub-Release:**
   - Git-Tag `v<VERSION>` auf den Commit der Änderung.
   - Release-Titel: `GBF-Extract v<VERSION>`; Release-Notes = der
     `CHANGELOG.md`-Eintrag dieser Version.
   - Die frisch gebaute `dist/GBF-Extract_v<VERSION>.exe` wird als
     Release-Asset hochgeladen (Asset-Name = Exe-Dateiname).
   - Releases bleiben anonymisiert (keine Herkunfts-/Inhaltshinweise).
2. **Speicherplatz-Regel — Exe nur im neuesten Release:**
   Nur das **jüngste Release** hält die `.exe` als Asset vor. Sobald ein
   neues Release veröffentlicht wird, wird das `.exe`-Asset des
   vorherigen Releases gelöscht; Release-Seite und Notes bleiben
   bestehen (jede Version ist per `build.py` reproduzierbar).
3. **Umsetzung via `gh`:**

   ```
   gh release create v<X.Y.Z> dist/GBF-Extract_v<X.Y.Z>.exe \
       --title "GBF-Extract v<X.Y.Z>" --notes "<changelog-eintrag>"
   gh release delete-asset v<ALT> GBF-Extract_v<ALT>.exe --yes
   ```

## Formatwissen (Reverse Engineering Stand)

- Ab Offset `0x1000` bis EOF liegt **ein durchgehender AES-256-CBC-Strom**.
- Schlüssel = `SHA-256(passwort_utf8)`.
- IV beeinflusst nur die ersten 16 Bytes; er wird per Known-Plaintext
  (`<?xml version="1`) zurückgerechnet.
- Header `0x0000-0x0FFF`: Salt + Sektionsverzeichnis (0xA00, 48-Byte-Einträge:
  Samples, Events, EventData, EventTypes, MediaChannels, VCAData),
  media_size @0x38, meta_len @0x58.
- `0x1000`: ExportInfo-XML. `0x2000`: Mediendaten (Records).
  `media_end`: Index-Region (72-Byte-Einträge).
- **Record-Header (72 Byte):** `d2 38 0c c4` @+0x0C, `0xff` + u24-**ms-
  Zeitstempel** @+0x10-0x13, `0x02` @+0x14 für Video-Records,
  `80 07 38` ~+0x20/+0x21 (zwei Varianten), Typwort `00 04 0x 02` @+0x30.
- **Video-Record-Daten:** H.264-Annex-B-NALs; danach folgen VCA-/Metadaten-
  Chunks mit demselben `00 00 01`-Framing, aber **ungültigem NAL-Header**
  (fzb=1 oder Typ∉{1,5,6,7,8,9}) → dort abbrechen.
- **Event-Records:** UTF-16LE-Schlüssel/Wert-Text nach der Signatur.
- **Reihenfolge:** Records sind in ~2–3er-Gruppen verwürfelt gespeichert;
  die u24-ms-Zeitstempel ergeben nach Sortierung die Präsentationsreihenfolge.
- **Multi-Kamera:** die u32 @Header+0x08 ist ein **pro-Kanal monotoner
  Sequenzzähler** — ts-sortierte Records werden per Greedy-Best-Fit in
  monotone u-Teilfolgen zerlegt (jede = eine Kamera, auch bei identischem
  SPS); Mini-Reststreams (<64) werden in den nächstgelegenen Haupt-Stream
  zurückgemergt. Referenzdatei: 2 Kameras à ~1926 Samples.
- Kein öffentliches GBF-Format-Dokument bekannt; alle Erkenntnisse aus
  Analyse der Beispieldatei.

## Test / Verifikation

- Extraktion muss XML-Metadaten, `.264` (durch ffmpeg/VLC abspielbar) und
  `.mp4` liefern.
- Referenzdatei: lokaler G-Core-Export (62,9 MB, **2 Kameras**,
  3856 Video-Records, ~485 s) — enthält reale Überwachungsbilder,
  **nicht weitergeben/committen**. Dateiname/Kundenname bewusst nicht
  in der Doku.
