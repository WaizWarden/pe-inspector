import argparse
import math
import pefile


class Inspector:
    def __init__(self):
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("filename", help="The name of the file to parse")
        self.args = self.parser.parse_args()
        self.pe = None

    def load_file(self):
        try:
            self.pe = pefile.PE(self.args.filename)

        except FileNotFoundError:
            print(f"Error: File not found at {self.args.filename}")
            exit(1)

        except pefile.PEFormatError:
            print(f"Error: Invalid PE file format")
            exit(1)

        except Exception as e:
            print(f"Unexpected error while loading file: {e}")
            exit(1)


    def parse_sections_for_entropy(self):
        try:
            for section in self.pe.sections:
                data = section.get_data()
                name = section.Name.decode(errors='ignore').strip('\x00')
                entropy = Inspector.entropy(data)
                size = len(data)
                print(f"{name}")
                print(f"    ENTROPY : {entropy:.2f}")
                print(f"    SIZE : {size}B\n")

        except Exception as e:
            print(f"Exception occurred while parsing sections: {e}")
            exit(1)

    def parse_iat(self):
        try:
            self.pe.parse_data_directories()

            if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                print(f"No IAT found")
                return

            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                print(f"--- {dll_name} ---")

                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                    else:
                        func_name = f"Ordinal {imp.ordinal}"

                    print(f"{func_name}")

        except Exception as e:
            print(f"Exception occurred while parsing IAT: {e}")
            exit(1)

    @staticmethod
    def entropy(data):
        if not data:
            return 0

        counts = [0] * 256
        for b in data:
            counts[b] += 1
        n = len(data)
        return -sum((c / n) * math.log2(c / n) for c in counts if c > 0)


if __name__ == '__main__':
    inspector = Inspector()
    inspector.load_file()
    inspector.parse_sections_for_entropy()
    inspector.parse_iat()
