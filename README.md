# PWN Hacking Tool (wrap-up + README v0)

**pwn_hacking_tool** to analityczny framework dla pwn/CTF, który automatycznie analizuje binarki ELF, koreluje wyniki z istniejących narzędzi i generuje realistyczne scenariusze exploitacyjne (ret2win, ret2libc, format string, ROP) zamiast samych surowych danych. Nie exploit-uje, nie brute-force’uje — myśli jak pwner.

## 0. Jednozdaniowa definicja projektu

pwn_hacking_tool to framework analityczny dla pwn/CTF, który automatycznie analizuje binarki ELF, koreluje wyniki z istniejących narzędzi i generuje realistyczne scenariusze exploitacyjne (ret2win, ret2libc, format string, ROP), zamiast tylko surowych danych.

## 1. Główne cele projektu (SMART)

**Cel główny:** skrócić czas „dostałem binarkę” → „mam sensowny plan exploita” z ~30–60 minut do kilku minut.

**Cele szczegółowe:**
1. Automatycznie: wykrywać najczęstsze podatności pwn, identyfikować źródła info-leaków, oceniać realną exploitable-ność.
2. Dostarczać: konkretne hinty exploitacyjne, artefakty przydatne pwnerowi (adresy, offsety, skeletony).
3. Być: modularne, rozszerzalne, oparte na istniejących narzędziach.

## 2. Zakres projektu (TAK / NIE)

**TAK:** analiza statyczna, korelacja wyników, heurystyki pwn, raportowanie, exploit templates.

**NIE:** automatyczne exploity, brute-force, fuzzing (na razie), bypass zabezpieczeń.

## 3. Najważniejsze problemy pwn, które narzędzie adresuje

**Podatności:** stack buffer overflow, format string, heap UAF/double free (future), logic bugs.

**Info-leaki:** format string leaks, GOT/PLT leaks, stack leaks, debug output.

**Techniki:** ret2win, ret2libc, ROP, shellcode (NX off), SROP (future).

## 4. Architektura wysokiego poziomu

```
INPUT
 ↓
[Extractor]
 ↓
[File Classifier]
 ↓
[Tool Adapters]
 ↓
[BinaryContext Builder]
 ↓
[Detectors]
 ↓
[Exploitability / Hint Engine]
 ↓
[Report & Artifacts]
```

Każdy etap ma jedną odpowiedzialność i komunikuje się przez wspólny model danych.

## 5. Kluczowy koncept: BinaryContext

BinaryContext to **jedyne źródło prawdy** dla detektorów i hint engine. Detektory nie uruchamiają CLI i nie parsują objdumpa — operują tylko na kontekście.

## 6. Technologie i narzędzia

**Core:** Python 3.10+, subprocess/asyncio, JSON/YAML.

**Adaptery (v0.1):** checksec, objdump, strings, file, nm.

## 7. Detectors (v1)

- Stack Overflow Detector (brak canary + dangerous imports + buffer clues)
- Format String Detector (printf + %p/%n + GOT writable)
- Ret2win Detector (brak PIE + funkcja win + overflow)
- Ret2libc Detector (NX on + leak + libc dynamiczna)

## 8. Exploitability & Hint Engine

Koreluje podatności + zabezpieczenia + symbole i wybiera najbardziej prawdopodobne ścieżki.

## 9. Output

- Raporty: text, JSON, Markdown.
- Artefakty: adresy, offsety, GOT/PLT, skeleton exploita (bez uruchamiania).

## 10. Roadmapa

- **v0.1**: ELF, checksec + objdump + strings, stack overflow + ret2win, raport.
- **v0.2**: readelf + nm, ret2libc, hint engine.
- **v0.3**: radare2, gdb headless, exploit templates.

---

# Implementacja v0.1 (ten repozytorium)

## Struktura

```
.
├── pwn_hacking_tool/
│   ├── adapters.py
│   ├── cli.py
│   ├── context.py
│   ├── detectors.py
│   ├── hints.py
│   ├── report.py
│   └── utils.py
├── pyproject.toml
└── README.md
```

## Szybki start

```bash
python -m pwn_hacking_tool.cli ./chall
python main.py ./chall
```

### Format wyjścia

```bash
python -m pwn_hacking_tool.cli ./chall --format json --output report.json
python -m pwn_hacking_tool.cli ./chall --format markdown --output report.md
```

## Architektura danych (BinaryContext)

Minimalny schema danych generowany przez `BinaryContext`:

```yaml
binary:
  path: chall
  arch: amd64
  stripped: true

protections:
  nx: true
  pie: false
  canary: false
  relro: partial

symbols:
  functions:
    - name: main
      addr: 0x401080
    - name: win
      addr: 0x401196
  imports:
    - gets
    - puts
    - printf

strings:
  interesting:
    - "/bin/sh"
    - "%p %p %p"
    - "FLAG{"

control:
  rip_control: likely
  arg_control: possible

leaks:
  stack: possible
  libc: likely
```

## Adaptery

Każde narzędzie jest opakowane w adapter: uruchomienie → parser → normalizacja → cache w `metadata`.

## Detectors & Hint Engine

Detektory produkują `findings`, hint engine wybiera ścieżki exploita i generuje krótkie skeletony payloadów (bez ich uruchamiania).
