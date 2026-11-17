# GBF-Extract

Entschlüsselt und extrahiert **Geutebrück G-Core Backup Files** (`.gbf`) —
z. B. Videosicherungen, die mit `GView32.exe`/`GView64.exe` abgespielt werden.
Dieses Tool ersetzt den Original-Viewer, wenn dieser nicht mehr lesbar/
verfügbar ist (z. B. beschädigte CD).

## Warum dieses Tool existiert

Geutebrück-G-Core-Systeme exportieren Beweissicherungen ausschließlich als
`.gbf`-Archiv zusammen mit einem proprietären Standalone-Viewer
(`GView32.exe`/`GView64.exe`), der **nur auf dem jeweiligen Export-Medium
mitgeliefert** wird. Einen unabhängigen Client zum Download stellt der
Hersteller nicht bereit.

Ist das Export-Medium beschädigt — zerkratzt, falsch beschriftet oder
teilweise unleserlich —, wird die Sicherung faktisch unbrauchbar, obwohl
die Videodaten selbst vollständig und intakt sind. Genau dieser Fall war
der Auslöser: Auf den Viewer-Dateien war ein Datenträger unleserlich
geworden, der Inhalt der Sicherung aber weiterhin vollständig vorhanden.

Dieses Tool ist der Workaround für diese Situation: Es entschlüsselt den
Export mit dem bei der Übergabe mitgelieferten Passwort, extrahiert alle
enthaltenen Videostreams und erzeugt zusätzlich eine druckfähige
Dokumentation — damit man mit solchen Sicherungen überhaupt arbeiten
kann, wenn der Hersteller keinerlei Clients freigibt.

> **Rechtlicher Hinweis / Clean-Room-Erklärung:** Dieses Tool wurde
> ausschließlich aus einer `.gbf`-Beispieldatei, dem dazugehörigen
> Export-Passwort und **Reverse Engineering** (dokumentiert in
> `CHANGELOG.md`/`AGENTS.md`) entwickelt. Es wurden **keinerlei Teile**
> der Original-Programme `GView32.exe`/`GView64.exe` verwendet — weder
> Code, Ressourcen noch Binärdaten; der Original-Viewer war zum
> Entwicklungszeitpunkt nicht einmal lesbar. Das Tool enthält damit
> keine urheberrechtlich geschützten Bestandteile des Herstellers.
>
> Es dient der Wiederherstellung und Dokumentation eigener bzw.
> berechtigt zugänglicher Beweissicherungen und umgeht **keine**
> Verschlüsselung — das beim Export vergebene Passwort wird weiterhin
> benötigt. Es besteht kein Bezug zu Geutebrück; „G-Core" ist eine
> Marke der Geutebrück GmbH.

## Features

- AES-256-CBC-Entschlüsselung des GBF-Exports mit dem mitgelieferten Passwort
- Extraktion der Export-Metadaten (`*_ExportInfo.xml`)
- Extraktion aller Video-Streams als H.264 Annex-B (`*.264`, abspielbar in
  VLC/mpv/ffmpeg)
- Umwandlung in `.mp4` mit **echtem Zeitstempel-Timing** (eigener
  Pure-Python-Muxer, kein ffmpeg nötig)
- Event-Log (`*_events.txt`) mit den im Export enthaltenen UTF-16-Eventdaten
- **Multi-Kamera-Trennung**: Kameras werden über den pro-Kanal monotonen
  Sequenzzähler (Header +0x08) getrennt — auch wenn sie identische SPS
  benutzen
- **GUI + CLI**: Start ohne Argumente öffnet eine grafische Oberfläche mit
  Drag&Drop-Feld, Passwort-Eingabe und Live-Log; mit Argumenten läuft das
  Tool als Kommandozeilen-Programm
- **DIN-A4-PDF-Bericht** pro Export: Quelldatei-Fakten inkl. SHA-256-Hash,
  Export-Metadaten, Standbild + Statistiken je Kamera, Event-Daten und
  rohe XML — druckfertig für die Akte
- Export-Ordner heißt immer wie die `.gbf`-Datei (`<ziel>/<dateiname>/`)

## Build (Windows .exe)

Voraussetzung: Python 3.x + `pip install -r requirements.txt`

```
python build.py
```

Ergebnis: `dist/GBF-Extract_v<VERSION>.exe` — **eine Datei, alle
Abhängigkeiten integriert**, lauffähig auf frischem Windows 11 ohne
Internet und ohne Python-Installation.

## Benutzung

### GUI (Standard)

Exe ohne Argumente starten (Doppelklick):

```
GBF-Extract_v1.2.0.exe
```

- `.gbf`-Datei auf den dunklen **Drag&Drop-Bereich** ziehen oder über
  „Datei wählen…" / Klick auf den Bereich auswählen
- **Passwort** eingeben (maskiert; Checkbox „anzeigen" macht es sichtbar)
- Zielordner wählen — der **Export-Ordner heißt immer wie die .gbf-Datei**
  und wird darin angelegt (Default: Ordner der .gbf)
- Optionen: MP4 / Raw-.264 / PDF-Bericht
- „Extrahieren" → Fortschritt und Ergebnis-Dateien erscheinen im Log-Feld

### Kommandozeile

```
GBF-Extract_v1.3.0.exe <datei.gbf> [-p PASSWORT] [-o zielordner] [--no-mp4] [--no-raw] [--no-report] [--fps N]
```

- `-p PASSWORT` — Export-Passwort direkt übergeben
- `--password-file DATEI` — Passwort aus Datei lesen
- ohne `-p` — interaktive Abfrage (Passwort wird nicht angezeigt)
- `-o ORDNER` — Zielordner; der Export-Ordner `<ORDNER>/<dateiname>/`
  wird darin angelegt (Standard: Verzeichnis der .gbf)
- `--no-mp4` / `--no-raw` — nur eine Ausgabeart
- `--no-report` — kein DIN-A4-PDF erzeugen
- `--fps` — Fallback-Bildrate, falls keine Zeitstempel nutzbar (Standard 25)

Beispiel:

```
GBF-Extract_v1.3.0.exe <export>.gbf
GBF-Extract_v1.3.0.exe <export>.gbf --password-file passwort.txt -o D:\exporte
```

### Ausgabedateien

| Datei | Inhalt |
|---|---|
| `*_ExportInfo.xml` | entschlüsselte Export-Metadaten (Kanalname, Zeitraum, Quellpfad, Version) |
| `*_events.txt` | UTF-16-Eventdaten (z. B. ObjectDirection, AutoLogin_User) |
| `*_camN.264` | H.264-Rohstream je Kamera (forensisch vollständig) |
| `*_camN.mp4` | abspielbarer MP4-Container mit Original-Timing |
| `*_report.pdf` | DIN-A4-Bericht: Dateifakten + SHA-256, Metadaten, Standbild + Stats je Kamera, Events, Roh-XML |

## Ablauf / Reverse-Engineering-Protokoll

1. **Datei analysiert**: Kein Klartext-Magic; ab `0x1000` hohe Entropie
   → verschlüsselt. Header `0x0000-0x0FFF` enthält Salt +
   Sektionsverzeichnis bei `0xA00` (48-Byte-Einträge: `Samples`, `Events`,
   `EventData`, `EventTypes`, `MediaChannels`, `VCAData`).
2. **Crypto gefunden**: `SHA-256(Passwort)` als AES-256-Key; der ganze Rest
   der Datei ist **ein** CBC-Strom. IV per Known-Plaintext
   (`<?xml version="1`) zurückgerechnet — danach entschlüsselt `0x1000`
   ein `ExportInfo`-XML mit Kanalname, Host, Zeitraum usw.
3. **Mediendaten**: ab `0x2000` Records mit 72-Byte-Headern
   (`d2 38 0c c4`-Signatur @+0x0C). Video-Records enthalten H.264-Annex-B-
   NALs (`00 00 00 01`/`00 00 01` Framing). Am Datenende hängen
   VCA-/Metadaten-Chunks — erkennbar an ungültigem NAL-Header
   (forbidden-bit oder reservierter Typ).
4. **Reihenfolge**: Records sind in ~2–3er-Blöcken verwürfelt; das
   u24-Feld @+0x11 ist ein **ms-Zeitstempel** → Sortierung ergibt die
   Präsentationsreihenfolge (bei der Referenzdatei ~8 fps, 485 s).
5. **Multi-Stream**: die u32 @Header+0x08 ist ein **pro-Kanal monotoner
   Sequenzzähler** — ts-sortierte Records werden in monotone u-Teilfolgen
   zerlegt; jede Teilfolge = eine Kamera (Referenzdatei: 2 Kameras,
   1930/1926 Samples, eigene IDR-Kadenzen ~3,8 s). Mini-Reststreams aus
   Schreib-Reordering werden zurückgemergt.
6. **MP4-Mux**: Pure-Python-`avc1`-Writer; SPS/PPS → `avcC`
   (inkl. High-Profile-Trailer-Bytes), Sample-Timing aus den ms-Stamps.
7. **Verifikation**: extrahierte `.264`/`.mp4` dekodieren fehlerfrei
   (1920×1080, ~2065 Frames, ~485 s; Bildinhalt = realer
   Kamera-Ausschnitt ✓).

## Versionierung

- `__version__` in `src/gbf_extract.py`
- Jede Codeänderung ⇒ Version hochzählen, `CHANGELOG.md`-Eintrag
- Release-Exe: `GBF-Extract_v<VERSION>.exe`
- Jede Version ⇒ GitHub-Release (Tag + Release + Exe-Asset); die `.exe`
  wird nur im jeweils **neuesten** Release vorgehalten, bei älteren
  Releases wird das Asset aus Speicherplatzgründen entfernt
  (Details: `AGENTS.md` → „GitHub-Release-Prozess")

## Dateien im Projekt

```
src/gbf_extract.py   Hauptprogramm (Crypto, Record-Parser, MP4-Muxer, GUI + CLI)
build.py             PyInstaller-Build (erzeugt versionierte Exe)
requirements.txt     Python-Abhängigkeiten
AGENTS.md            Projektregeln / Formatwissen
CHANGELOG.md         Versionshistorie
README.md            diese Datei
LICENSE              MIT-Lizenz
.gitignore           schliesst Backups, Exporte, Passwörter, Build-Artefakte aus
```

## Hinweise / Grenzen

- Der Export kann **mehrere Kameras** enthalten — diese werden über den
  Kanal-Sequenzzähler in getrennte Dateien geschrieben (`_cam0`, `_cam1`,
  …). Die Referenzdatei enthält zwei Kameras (Innenraum + Eingang).
- Die Wasserzeichen-/Authentizitäts-Prüfung des Original-Viewers wird nicht
  nachgebildet; die Extraktion verändert die Quelldatei nicht.
- Event-Daten werden als Text extrahiert (Schlüsselnamen + Werte); die
  vollständige G-Core-Event-Semantik ist proprietär.
- Passwort wird benötigt und **nicht** gespeichert.
