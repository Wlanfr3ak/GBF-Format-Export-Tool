# Changelog — GBF-Extract

## [1.3.2] — 2026-03-08

### Dokumentation (keine Code-Änderung)

- AGENTS.md: neuer Abschnitt **„GitHub-Release-Prozess"** —
  jede Version wird als GitHub-Release (Tag `v<VERSION>`,
  Titel `GBF-Extract v<VERSION>`, Notes aus dem Changelog) mit der
  gebauten Exe als Asset veröffentlicht; aus Speicherplatzgründen
  wird das `.exe`-Asset jeweils nur im **neuesten Release**
  vorgehalten und bei älteren Releases gelöscht (ältere Versionen
  bleiben per `build.py` reproduzierbar). Beispiel-`gh`-Kommandos
  dokumentiert.

## [1.3.1] — 2026-03-08

### Veröffentlichungs-Vorbereitung (keine Code-Änderung)

- **Repo-Bereinigung:** Referenz-Backup, Passwort-Datei und alle
  Export-Ausgabeordner (echtes Videomaterial, Metadaten, PDFs) aus dem
  Projektordner entfernt — keinerlei Spuren zu Inhalt oder Herkunft der
  ursprünglichen Sicherung mehr im Repository.
- **`LICENSE`** hinzugefügt (MIT).
- **`.gitignore`** hinzugefügt: schließt `*.gbf`, `*.264`, `*_report.pdf`,
  Export-/Event-Dateien, Passwort-Dateien und Build-Artefakte
  (`build/`, `dist/`, `*.spec`, `__pycache__`) aus.
- README: neuer Abschnitt **„Warum dieses Tool existiert"** — erklärt,
  dass G-Core-Exporte nur mit einem proprietären Viewer auf dem
  Export-Medium ausgeliefert werden, der Hersteller keinen eigenständigen
  Client freigibt und das Tool deshalb als Workaround für beschädigte
  Medien entstand; inkl. Rechtshinweis (kein Umgehen der Verschlüsselung,
  Passwort weiterhin nötig).
- Build-Artefakte (`build/`, `*.spec`, `__pycache__`) gelöscht — werden
  von `build.py` bei Bedarf neu erzeugt.

## [1.3.0] — 2026-03-08

### PDF-Bericht & Export-Ordner-Struktur

- **Export-Ordner heißt immer wie die `.gbf`-Datei** (ohne Endung):
  `-o`/Zielordner ist jetzt das *Eltern*-Verzeichnis, darin wird
  `<dateiname>/` angelegt. Default = Verzeichnis der `.gbf` selbst —
  der Export landet also direkt neben der Quelldatei.
- **DIN-A4-PDF-Bericht** (`<dateiname>_report.pdf`) pro Export, zum
  Ausdrucken/Ablegen in einer Akte:
  - Quelldatei-Fakten: Name, Größe, **SHA-256-Beweishash**
  - Export-Metadaten als Tabelle (alle Felder der ExportInfo.xml inkl.
    MediaChannel-Liste)
  - je Kamera: Statistiken (Samples, NALs, Auflösung, Dauer, Dateinamen)
    + **Standbild aus der Video-Mitte** (dekodiert via PyAV → PNG)
  - Event-Daten-Auszug + komplettes ExportInfo.xml als Rohdaten
  - Kamera-Blöcke werden zusammengehalten (kein Bild ohne Beschriftung
    auf der Folgeseite)
- GUI: Checkbox „PDF-Bericht (DIN A4)"; Zielordner-Feld vorbefüllt mit
  dem Ordner der gewählten `.gbf` + Hinweis „Unterordner = Dateiname".
- CLI: `--no-report` schaltet den PDF-Export ab.

### Abhängigkeiten / Build

- Neu: `fpdf2` (PDF-Erzeugung, rein Python), `av`+`Pillow` (Standbild-
  Dekodierung); werden per `--collect-all`/`--hidden-import` gebündelt.
- Exe-Größe steigt auf ~70 MB (PyAV bringt FFmpeg-DLLs mit) — weiterhin
  single-file und offline-fähig.

### Doku

- README/CHANGELOG/AGENTS.md **anonymisiert**: echter Dateiname,
  Kundenname und Kamera-/Ortsbezeichnungen durch neutrale Platzhalter
  ersetzt; `tools/re_try_decrypt.py` liest Datei+Passwort nun aus argv
  (kein hartkodiertes Passwort mehr).

## [1.2.0] — 2026-03-08

### GUI hinzugefügt

- **Grafische Oberfläche** (Tkinter): `.gbf`-Datei per **Drag&Drop** auf den
  markierten Bereich ziehen oder per Dateidialog („Datei wählen…")
  auswählen, **Passwort-Feld** (maskiert, mit „anzeigen"-Checkbox),
  Ausgabeordner-Wahl, Optionen für MP4-/Raw-Ausgabe und Live-Log der
  Extraktion.
- Drag&Drop über `tkinterdnd2` (im Bundle enthalten); ohne die Bibliothek
  fällt die GUI sauber auf Dateidialog-only zurück.
- Extraktion läuft in einem Worker-Thread — die GUI bleibt responsiv,
  Fortschritt/Log erscheinen im Textfenster.
- **Dual-Mode:** Start ohne Argumente → GUI; mit CLI-Argumenten → bisherige
  Kommandozeilen-Nutzung (unverändert).

### Build

- Python 3.15 liefert Tcl/Tk 9 als Zip-Archive (`libtcl9.0.4.zip`,
  `libtk9.0.4.zip` unter `<prefix>/tcl`) — PyInstaller 6.21 kennt dieses
  Layout noch nicht. `build.py` entpackt die Archive nun in `build/tcl_stage`
  und bundelt sie als `_tcl_data`/`_tk_data` (vom PyInstaller-Runtime-Hook
  erwartet).
- Neue Build-Flags: `--hidden-import _tkinter/tkinter/tkinter.ttk/
  tkinterdnd2`, `--collect-all tkinterdnd2`, `--add-data` für Tcl/Tk-Data.
- `requirements.txt`: `tkinterdnd2>=0.4` ergänzt.

## [1.1.0] — 2026-03-08

### Multi-Kamera-Trennung (Fix)

**Problem:** Die extrahierten Streams schwankten zwischen verschiedenen
Perspektiven mit sichtbaren Dekodier-Artefakten — die Referenzdatei enthält
**zwei Kameras**, deren Encoder identische SPS-Bytes benutzen, sodass die
SPS-Hash-Gruppierung (v1.0.0) beide in einen Stream mischte.

**Ursache:** G-Core schreibt die Records aller Kanäle verzahnt in dieselbe
Medienregion; mehrere Kameras mit gleicher Encoder-Konfiguration erzeugen
gleiche SPS/PPS.

**Lösung:** Der u32-Wert im Record-Header @+0x08 ist ein **pro Kanal
monotoner Sequenzzähler** (vermutlich Slot-/Record-Index des jeweiligen
Kanals im Aufzeichnungsbuffer). Die Records werden nun nach Zeitstempel
sortiert und per Greedy-Best-Fit in monotone u-Teilfolgen zerlegt — jede
Teilfolge = eine Kamera. Verifiziert an der Referenzdatei:

- `cam0`: 1930 Samples — Perspektive A (Innenraum)
- `cam1`: 1926 Samples — Perspektive B (Eingangsbereich)
- beide Streams dekodieren fehlerfrei, ohne Perspektiv-Wechsel

**Details:**
- `iter_records()` liefert zusätzlich `chan` (u32 @+0x08).
- Mini-Reststreams (<64 Records, entstehen durch Zähler-Blips/
  Schreib-Reordering) werden in den nächstgelegenen Haupt-Stream
  zurückgemergt.
- Bei nur einer Kamera degeneriert der Split korrekt zu einem Stream.

### Sonstiges
- NAL-Filter auf tatsächlich verwendete Typen {1,5,6,7,8,9} eingeschränkt
  (GBF-Record-Trailer/VCA-Chunks benutzen reservierte Typen).
- MP4: stss/stts/tkhd/avcC-Boxen korrigiert; Sample-Timing aus echten
  ms-Zeitstempeln (per-Stream).

## [1.0.0] — 2026-03-08

Erste funktionsfähige Version nach abgeschlossenem Reverse Engineering der
Beispieldatei `referenz_export.gbf` (G-Core 7.0.0.60 Export).

### Reverse Engineering
- Verschlüsselung identifiziert: **AES-256-CBC** über den gesamten Bereich
  ab Offset `0x1000`, Schlüssel = `SHA-256(Passwort-UTF8)`.
- IV-Rückgewinnung über Known-Plaintext (`<?xml version="1`).
- Header-Layout dokumentiert: Salt, Sektionsverzeichnis (Samples, Events,
  EventData, EventTypes, MediaChannels, VCAData), Längenfelder.
- Record-Struktur entschlüsselt: 72-Byte-Header mit `d2 38 0c c4`-Signatur,
  `ff` + u24-ms-Zeitstempel, Typfeldern; zwei Header-Varianten.
- Video-Daten = H.264-Annex-B-NALs; VCA-/Metadaten-Chunks am Record-Ende
  werden anhand ungültiger NAL-Typen abgetrennt.
- Reihenfolge: Records sind verwürfelt gespeichert; Zeitstempel-Sortierung
  liefert die Präsentationsreihenfolge (~8 fps effektiv, 485 s Video).
- Event-Records: UTF-16LE-Textblobs werden extrahiert.
- Multi-Kamera-Unterstützung: Gruppierung der NALs nach SPS-Hash.

### Implementierung
- `src/gbf_extract.py`: CLI-Tool mit Passwort-Eingabe
  (-p / --password-file / interaktiv via getpass).
- Ausgaben: `_ExportInfo.xml`, `_events.txt`, `_<cam>.264` (Annex-B),
  `_<cam>.mp4` (eigener Pure-Python-MP4-Muxer mit echtem per-Sample-Timing,
  avc1/avcC inkl. High-Profile-Trailer).
- Verifikation: extrahierte Streams dekodieren fehlerfrei (1920×1080,
  3856 Samples, ~2065 Frames, ~485 s).
- `build.py`: PyInstaller-OneFile-Build; Exe-Name enthält die Version
  (`GBF-Extract_v1.0.0.exe`).

### Dokumentation
- `AGENTS.md` mit Projektregeln (Versionspflicht, Exe-Namenschema,
  Changelog-Pflicht, Offline-Ziel, Passwort-Handling, Quellschutz).
- `README.md` mit Schritt-für-Schritt-Protokoll des Reverse Engineering.
- `requirements.txt` (pycryptodome, pyinstaller).
