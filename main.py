import datetime
import os
import sys

from textual.app import App, ComposeResult
from textual.containers import ScrollableContainer, Horizontal
from textual.widgets import Footer, DataTable, Label, Button, ContentSwitcher, ListView, ListItem

from CSS import STYLES
from inspector import Inspector


class SimpleInspectorUI(App):
    BINDINGS = [("q", "quit", "Quit")]
    CSS = STYLES

    def __init__(self, inspector: Inspector):
        super().__init__()
        self.inspector = inspector
        self.iat_data = {}

    def compose(self) -> ComposeResult:
        with Horizontal(id="top-bar"):
            yield Button("Entropy & Headers", id="btn-entropy", variant="primary")
            yield Button("IAT (Imports)", id="btn-iat")
            yield Button("Digital Signature", id="btn-signature")

        with ContentSwitcher(initial="pane-entropy"):
            with Horizontal(id="pane-entropy", classes="pane"):
                with Horizontal(classes="split-container"):
                    with ScrollableContainer(id="entropy-right-panel", classes="sub-panel"):
                        yield Label("[b]PE SECTIONS[/b]\n")
                        yield DataTable(id="sections-table")

                    with ScrollableContainer(classes="sub-panel wide-panel"):
                        yield Label("[b]General[/b]\n")
                        yield Label(id="general-info")

            with Horizontal(id="pane-iat", classes="pane"):
                with Horizontal(classes="split-container"):
                    with ScrollableContainer(classes="sub-panel"):
                        yield Label("[b]Library Modules[/b]\n")
                        self.iat_data = self.inspector.get_iat_data()

                        list_items = []
                        for index, dll in enumerate(self.iat_data.keys()):
                            list_items.append(ListItem(Label(dll), id=f"dll-{index}"))

                        yield ListView(*list_items, id="dll-list")

                    with ScrollableContainer(id="iat-right-panel", classes="sub-panel wide-panel"):
                        yield Label("[b]Imported Functions[/b]\n")
                        yield DataTable(id="imports-table")

            with Horizontal(classes="pane", id="pane-signature"):
                with ScrollableContainer():
                    yield Label("[b]Primary Signature[/b]\n")
                    yield Label(id="cert-info-label")

        yield Footer()

    def on_mount(self) -> None:
        sec_table = self.query_one("#sections-table", DataTable)
        sec_table.add_columns("Section Name", "Entropy", "Size")
        sections = self.inspector.get_sections_entropy()
        sec_table.add_rows(sections)

        self.update_general()
        self.update_certificates()

        if self.iat_data:
            first_dll = list(self.iat_data.keys())[0]
            self.update_functions_view(first_dll)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        switcher = self.query_one(ContentSwitcher)
        self.query_one("#btn-entropy", Button).variant = "default"
        self.query_one("#btn-iat", Button).variant = "default"
        self.query_one("#btn-signature", Button).variant = "default"

        if event.button.id == "btn-entropy":
            event.button.variant = "primary"
            switcher.current = "pane-entropy"
        elif event.button.id == "btn-iat":
            event.button.variant = "primary"
            switcher.current = "pane-iat"
        elif event.button.id == "btn-signature":
            event.button.variant = "primary"
            switcher.current = "pane-signature"

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.list_view.id == "dll-list" and event.item is not None:
            dll_keys = list(self.iat_data.keys())
            item_index = event.list_view.index
            if item_index is not None and 0 <= item_index < len(dll_keys):
                target_dll = dll_keys[item_index]
                self.update_functions_view(target_dll)

    def update_functions_view(self, dll_name: str) -> None:
        table = self.query_one("#imports-table", DataTable)
        table.clear()
        table.add_rows(self.iat_data.get(dll_name, []))

    def update_certificates(self):
        cert_label = self.query_one("#cert-info-label", Label)
        result = self.inspector.get_signature()

        if len(result) == 0:
            cert_info = "[red][b]NO CERTIFICATE FOUND[/b][/red]\n\n"

        else:
            sig_data = result[0]
            cert_info = (
                f"[b]Signing Time:[/b]  {sig_data.get('Signing time')}\n"
                f"[b]Serial Number:[/b] {sig_data.get('Serial Number')}\n"
                f"[b]Issuer:[/b]        {sig_data.get('Issuer')}\n\n"

                f"[b]Countersigner Signing time:[/b]  {sig_data.get('Countersigner Signing time')}\n"
                f"[b]Countersigner Serial Number:[/b] {sig_data.get('Countersigner Serial Number')}\n"
                f"[b]Countersigner Issuer:[/b]        {sig_data.get('Countersigner Issuer')}\n"
            )

        cert_label.update(cert_info)

    def update_general(self):
        timestamp = self.inspector.pe.FILE_HEADER.TimeDateStamp
        compile_time = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).strftime(
            '%Y-%m-%d %H:%M:%S UTC')
        general_label = self.query_one("#general-info", Label)
        f"[b]Machine:[/b]   {self.inspector.pe.FILE_HEADER.Machine}\n\n"

        machine = "N/A"
        if int(self.inspector.pe.FILE_HEADER.Machine) == 34404:
            machine = "64-bit"
        elif int(self.inspector.pe.FILE_HEADER.Machine) == 332:
            machine = "32-bit"

        info_text = (
            f"[b]MD5:[/b]\n{self.inspector.calculate_md5()}\n\n"
            f"[b]SHA-256:[/b]\n{self.inspector.calculate_sha256()}\n\n"

            f"[b]Filename:[/b]          {self.inspector.filename}\n"
            f"[b]File Size:[/b]         {os.path.getsize(self.inspector.filename):,} Bytes\n\n"
            f"[b]e_lfanew Offset:[/b]   {self.inspector.pe.DOS_HEADER.e_lfanew} Bytes\n"
            f"[b]Machine:[/b]           {machine}\n"
            f"[b]Compile Time:[/b]      {compile_time}\n"
            f"[b]Entry Point (RVA):[/b] 0x{self.inspector.pe.OPTIONAL_HEADER.AddressOfEntryPoint:08x}\n"
            f"[b]Image Base:[/b]        0x{self.inspector.pe.OPTIONAL_HEADER.ImageBase:08x}\n"
            f"[b]Size in RAM:[/b]       {self.inspector.pe.OPTIONAL_HEADER.SizeOfImage:,} Bytes\n"
        )
        general_label.update(info_text)

        imp_table = self.query_one("#imports-table", DataTable)
        imp_table.add_columns("Function Name", "Thunk Offset")


if __name__ == "__main__":
    if sys.version_info < (3, 11):
        print("Invalid version of python. Version 3.11 and above is required.")
        sys.exit(2)

    if len(sys.argv) < 2:
        print("Usage: python main.py <executable>")
        sys.exit(1)

    inspector_backend = Inspector(sys.argv[1])
    if not inspector_backend.load_file():
        print("Unable to read executable")
        sys.exit(1)

    app = SimpleInspectorUI(inspector_backend)
    app.run()
