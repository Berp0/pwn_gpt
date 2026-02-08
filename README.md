# PWN Binary Intelligence Tool v0.4

**pwn_hacking_tool** to modularny framework do głębokiej analizy binarek ELF pod kątem CTF pwn. Narzędzie **nie exploit‑uje**, **nie brute‑force’uje**, **nie zgaduje**. Buduje deterministyczny **BinaryKnowledgeContext**, liczy score’y ścieżek exploita i generuje raporty tekst/JSON/explain payload.

## Cel

Skrócić czas „mam binarkę” → „mam realny plan exploita” do kilku minut poprzez korelację danych z wielu narzędzi i heurystyk pwn.

---

## Architektura v0.4 (skrót)

```
ToolchainValidator
  ↓
Extractors (fingerprint, protections, imports, input, strings, GOT, callgraph)
  ↓
BinaryKnowledgeContext
  ↓
Heuristic Scoring Engine
  ↓
Exploit Path Synthesizer
  ↓
Report (text / json / explain)
```

### BinaryKnowledgeContext (core)

Single source of truth z polami: metadata, memory layout, protections, imports/symbols, input surface, control flow, leak surface, exploit primitives, toolchain, heuristic scores, exploit paths.

---

## Szybki start

```bash
python -m pwn_hacking_tool.cli ./chall
```

### Format wyjścia

```bash
python -m pwn_hacking_tool.cli ./chall --format json --output report.json
python -m pwn_hacking_tool.cli ./chall --format explain --output explain.json
```

### Walidacja narzędzi

```bash
python -m pwn_hacking_tool.cli --validate-tools
```

### Instalacja wymaganych narzędzi

```bash
python -m pwn_hacking_tool.cli --install-tools-only
```

**Security:** instalator używa wyłącznie zaufanych menedżerów pakietów (`apt-get`, `dnf`, `pacman`) bez `shell=True`. Nie pobiera nic z arbitralnych URL‑i i instaluje tylko znane narzędzia.

---

## Toolchain (wspierane narzędzia)

- checksec
- objdump
- readelf
- nm
- strings
- ldd
- ROPgadget
- radare2 (opcjonalnie)
- gdb (headless)

Brak narzędzia ≠ crash — Validator ustawia capability flags.

---

## GUI

```bash
python -m pwn_hacking_tool.gui
```

GUI pozwala wrzucić binarkę lub archiwum i skopiować raport do schowka.

---

## Output

- **Text report**: decyzje + uzasadnienia.
- **JSON**: pełny BinaryKnowledgeContext.
- **Explain payload**: skondensowany kontekst do LLM / write‑up.

---

## Wersja

Aktualna wersja: **v0.4**.
