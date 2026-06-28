import hashlib
import logging
import os
import datetime
import pefile
import numpy as np
from signify.authenticode import *


class Inspector:
    def __init__(self, filename: str):
        self.filename = filename
        self.pe = None
        self.signed_pe = None
        self.result = {
            "general": {},
            "signature": [],
            "entropy": [],
            "IAT": {}

        }

    def load_file(self) -> bool:
        try:
            self.pe = pefile.PE(self.filename, fast_load=True)
            return True
        except Exception as e:
            logging.error(f"Failed to load file: {e}")
            return False

    def get_sections_entropy(self) -> None:
        results = []

        def _calculate_entropy(buffer) -> float:
            if not buffer:
                return 0.0
            data = np.frombuffer(buffer, dtype=np.uint8)
            counts = np.bincount(data, minlength=256)
            probs = counts[counts > 0] / len(data)
            return float(-np.sum(probs * np.log2(probs)))

        # Calculate entropy of whole file
        try:
            full_data = self.pe.__data__  # __data__ contains whole loaded file
            full_entropy = _calculate_entropy(full_data)
            results.append((self.filename, f"{full_entropy:.2f}"))
        except Exception as e:
            logging.error(f"Error occurred while parsing file: {e}")

        # Calculate entropy of sections
        try:
            for section in self.pe.sections:
                data = section.get_data()
                name = section.Name.decode(errors='ignore').strip('\x00')
                size = len(data)

                entropy = _calculate_entropy(data)
                results.append((name, f"{entropy:.2f}", f"{size} B"))
        except Exception as e:
            logging.error(f"Error occurred while parsing sections of file: {e}")
        self.result["entropy"] = results

    def get_iat_data(self) -> None:
        iat_map = {}
        if not self.pe:
            self.result["IAT"] = iat_map
        try:
            self.pe.parse_data_directories()
            if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                self.result["IAT"] = iat_map

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
        except Exception as e:
            logging.error(f"Error occurred while parsing IAT: {e}")

        self.result["IAT"] = iat_map

    def get_signature(self) -> None:
        signature = []
        with open(self.filename, "rb") as f:
            primary = {}
            try:
                signed_file = AuthenticodeFile.from_stream(f)
                status, err = signed_file.explain_verify()
            except Exception as e:
                logging.error(f"File is unsigned or parsing failed: {e}")
                self.result["signature"] = []

            if status == AuthenticodeVerificationResult.NOT_SIGNED:
                primary["Trust Status"] = "Not Signed"
                self.result["signature"] = [primary]
            elif status == AuthenticodeVerificationResult.OK:
                primary["Trust Status"] = "Verified & Trusted Root"
            elif status == AuthenticodeVerificationResult.CERTIFICATE_ERROR:
                primary["Trust Status"] = "Untrusted/Fake Root (Possible Self-Signed)"
            elif status == AuthenticodeVerificationResult.INVALID_DIGEST:
                primary["Trust Status"] = "Tampered/Modified Binary"
            else:
                primary["Trust Status"] = f"Failed ({status.name})"

            # primary signature
            for signed_data in signed_file.signatures:
                if signed_data.signer_info:
                    primary["Signing time"] = signed_data.signer_info.signing_time
                    primary["Serial Number"] = signed_data.signer_info.serial_number
                    primary["Issuer"] = signed_data.signer_info.issuer

                cs = signed_data.signer_info.countersigner
                if cs and hasattr(cs, "signer_info"):
                    primary["Countersigner Signing time"] = cs.signer_info.signing_time
                    primary["Countersigner Serial Number"] = cs.signer_info.serial_number
                    primary["Countersigner Issuer"] = cs.signer_info.issuer

            signature.append(primary)

        self.result["signature"] = [primary]

    def get_general_info(self):

        machine = "N/A"
        if int(self.pe.FILE_HEADER.Machine) == 34404:
            machine = "64-bit"
        elif int(self.pe.FILE_HEADER.Machine) == 332:
            machine = "32-bit"

        timestamp = self.pe.FILE_HEADER.TimeDateStamp
        compile_time = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).strftime(
            '%Y-%m-%d %H:%M:%S UTC')

        general = {
            "MD5": self.calculate_md5(),
            "SHA-256": self.calculate_sha256(),
            "Filename": self.filename,
            "File Size (Bytes)": os.path.getsize(self.filename),
            "e_lfanew Offset (Bytes)": self.pe.DOS_HEADER.e_lfanew,
            "Machine": machine,
            "Compile Time": compile_time,
            "Entry Point (RVA)": f"0x{self.pe.OPTIONAL_HEADER.AddressOfEntryPoint:08x}",
            "Image Base": f"0x{self.pe.OPTIONAL_HEADER.ImageBase:08x}",
            "Size in RAM (Bytes)": self.pe.OPTIONAL_HEADER.SizeOfImage
        }

        self.result["general"] = general

    def calculate_sha256(self):
        try:
            with open(self.filename, "rb") as f:
                return hashlib.file_digest(f, "sha256").hexdigest()
        except Exception as e:
            logging.error(f"Error occurred while reading SHA256: {e}")
            return -1

    def calculate_md5(self):
        try:
            with open(self.filename, "rb") as f:
                return hashlib.file_digest(f, "md5").hexdigest()
        except Exception as e:
            logging.error(f"Error occurred while reading MD5: {e}")
            return -1
