# PE Inspector

A terminal UI tool for static analysis of Windows PE (Portable Executable) files

***

## Features
- **Entropy analysis** — calculates Shannon entropy for the whole file and each PE section
- **PE headers** — displays general metadata: MD5/SHA-256 hashes, file size, compile timestamp, machine architecture (32/64-bit), entry point (RVA), image base, in-memory size
- **IAT viewer** — lists all imported DLLs and their imported functions with thunk offsets
- **Digital signature pane** — WIP

***

## Install Requirements

```
pip install -r requirements
```


***

## Usage

```bash
python main.py <path/to/executable.exe>
```

**Example:**
```bash
python main.py C:\Windows\System32\notepad.exe
```

***

## Project Structure

```
.
├── main.py        # Textual UI app and entry point
├── inspector.py   # PE parsing backend (pefile wrapper)
└── CSS.py         # Textual CSS styles
```

***

