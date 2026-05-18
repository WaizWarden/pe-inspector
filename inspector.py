import pefile
import argparse
import math

class Inspector:
    def __init__(self):
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("filename", help="The name of the file to parse")
        self.args = self.parser.parse_args()

    def parse_file(self):

        try:
            pe = pefile.PE(self.args.filename)

            for section in pe.sections:
                data = section.get_data()
                name = section.Name.decode(errors='replace').strip('\x00')
                size = len(data)
                print(f"{name}:       ENTROPY={Inspector.entropy(data):.2f}     SIZE={size}B")

        except Exception as e:
            print(f"Exception occurred while loading file: {e}")
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
    inspector.parse_file()
