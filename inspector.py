import hashlib
import logging

import pefile
import numpy as np
from signify.authenticode import *


class Inspector:
    def __init__(self, filename: str):
        self.filename = filename
        self.pe = None
        self.signed_pe = None

    def load_file(self) -> bool:
        try:
            self.pe = pefile.PE(self.filename, fast_load=True)
            return True
        except Exception:
            logging.error(f"Failed to load file: {Exception}")
            return False

    def get_sections_entropy(self) -> list:
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
        except Exception:
            logging.error(f"Error occurred while parsing file: {Exception}")

        # Calculate entropy of sections
        try:
            for section in self.pe.sections:
                data = section.get_data()
                name = section.Name.decode(errors='ignore').strip('\x00')
                size = len(data)

                entropy = _calculate_entropy(data)
                results.append((name, f"{entropy:.2f}", f"{size} B"))
        except Exception:
            logging.error(f"Error occurred while parsing sections of file: {Exception}")
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
            logging.error(f"Error occurred while parsing IAT: {Exception}")
        return iat_map

    def get_signature(self) -> list:
        signature = []
        with open(self.filename, "rb") as f:
            primary = {}
            signed_file = AuthenticodeFile.from_stream(f)
            status, err = signed_file.explain_verify()

            if err:
                return []

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

            # embedded signature
            embedded_signatures = list(
                signed_file.iter_embedded_signatures(include_nested=True, ignore_parse_errors=True))
            len(embedded_signatures)

            for signature in embedded_signatures:
                logging.info(signature.signer_info.publisher_info)
                logging.info(signature.signer_info.signing_time)
                logging.info(signature.signer_info.serial_number)
                logging.info(signature.signer_info.issuer)

                cs = signature.signer_info.countersigner
                if cs and hasattr(cs, "signer_info") and cs.signer_info:
                    logging.info(f"Embedded TSA Timestamp: {cs.signer_info.signing_time}")
                    logging.info(f"Embedded TSA Serial Number: {cs.signer_info.serial_number}")
                    logging.info(f"Embedded TSA Issuer: {cs.signer_info.issuer}")

        if status != AuthenticodeVerificationResult.OK:
            logging.error(f"Invalid: {err}")

        return [primary]

    def calculate_sha256(self):
        try:
            with open(self.filename, "rb") as f:
                return hashlib.file_digest(f, "sha256").hexdigest()
        except Exception:
            logging.error(f"Error occurred while reading SHA256: {Exception}")
            return -1

    def calculate_md5(self):
        try:
            with open(self.filename, "rb") as f:
                return hashlib.file_digest(f, "md5").hexdigest()
        except Exception:
            logging.error(f"Error occurred while reading MD5: {Exception}")
            return -1
