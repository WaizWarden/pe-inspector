import hashlib
import math
import os

import pefile


class Inspector:
    def __init__(self, filename: str):
        self.filename = filename
        self.pe = None

    def load_file(self) -> bool:
        try:
            self.pe = pefile.PE(self.filename)
            return True
        except Exception:
            return False

    def get_sections_entropy(self) -> list:
        results = []

        # Calculate entropy of whole file
        try:
            if self.filename and os.path.exists(self.filename):
                with open(self.filename, "rb") as f:
                    full_data = f.read()

                full_entropy = self.entropy(full_data)
                display_name = f"{os.path.basename(self.filename)}"
                results.append((display_name, f"{full_entropy:.2f}"))
        except Exception:
            pass

        # Calculate entropy of sections
        try:
            for section in self.pe.sections:
                data = section.get_data()
                name = section.Name.decode(errors='ignore').strip('\x00')
                entropy = self.entropy(data)
                size = len(data)
                results.append((name, f"{entropy:.2f}", f"{size} B"))
        except Exception:
            pass
        return results

    def get_iat_data(self) -> dict:
        iat_map = {}
        if not self.pe:
            return iat_map
        try:
            self.pe.parse_data_directories()
            if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                return iat_map

            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                funcs = []
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                    else:
                        func_name = f"Ordinal {imp.ordinal}"

                    thunk_addr = f"0x{imp.address:08X}" if hasattr(imp, 'address') else "N/A"
                    funcs.append((func_name, thunk_addr))

                iat_map[dll_name] = funcs
        except Exception:
            pass
        return iat_map

    def calculate_sha256(self):
        try:
            with open(self.filename, "rb") as f:
                return hashlib.file_digest(f, "sha256").hexdigest()
        except Exception:
            return -1

    def calculate_md5(self):
        try:
            with open(self.filename, "rb") as f:
                return hashlib.file_digest(f, "md5").hexdigest()
        except Exception:
            return -1

    @staticmethod
    def entropy(data) -> float:
        if not data:
            return 0.0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        n = len(data)
        return -sum((c / n) * math.log2(c / n) for c in counts if c > 0)
