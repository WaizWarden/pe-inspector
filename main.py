import sys
import json

from signify.x509.certificates import CertificateName
from textual.app import App, ComposeResult, SystemCommand
from textual.containers import ScrollableContainer, Horizontal
from textual.widgets import Footer, DataTable, Label, Button, ContentSwitcher, ListView, ListItem
from textual.screen import Screen
from typing import Iterable

from CSS import STYLES
from inspector import Inspector


class InspectorApp(App):
    BINDINGS = [("q", "quit", "Quit")]
    CSS = STYLES

    def __init__(self, inspector: Inspector):
        super().__init__()
        self.inspector = inspector
        self.iat_data = {}

    def get_system_commands(self, screen: Screen) -> Iterable[SystemCommand]:
        for command in super().get_system_commands(screen):
            if command.title in ("Minimize", "Maximize", "Keys", "Theme", "Screenshot", "Quit"):
                continue
            yield command

        yield SystemCommand("Export JSON", "Exports data as json file", self.json_callback)

    def json_callback(self) -> None:
        try:
            # CertificateName is un-serializable
            # Convert it to string
            def fallback(obj):
                if isinstance(obj, CertificateName):
                    return str(obj)
                return repr(obj)

            with open("export.json", "w", encoding="utf-8") as f:
                json.dump(self.inspector.result, f, default=fallback, indent=1)

            self.notify("Export complete: export.json")
        except Exception as e:
            self.notify(f"Export failed: {str(e)}", severity="error")

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
                        self.inspector.get_iat_data()
                        self.iat_data = self.inspector.result["IAT"]

                        list_items = []
                        for index, dll in enumerate(self.iat_data.keys()):
                            list_items.append(ListItem(Label(dll), id=f"dll-{index}"))

                        yield ListView(*list_items, id="dll-list")

                    with ScrollableContainer(id="iat-right-panel", classes="sub-panel wide-panel"):
                        yield Label("[b]Imported Functions[/b]\n")
                        yield DataTable(id="imports-table")

            with Horizontal(classes="pane", id="pane-signature"):
                with ScrollableContainer():
                    yield Label("[b]Primary Signature[/b]\n\n")
                    yield Label(id="cert-info-label")

        yield Footer()

    def on_mount(self) -> None:
        sec_table = self.query_one("#sections-table", DataTable)
        sec_table.add_columns("Section Name", "Characteristics", "Entropy", "Size")
        self.inspector.get_sections_entropy()
        sections = self.inspector.result["entropy"]

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
        self.inspector.get_signature()
        result = self.inspector.result["signature"]

        if len(result) == 0:
            cert_info = "[red][b]NO CERTIFICATE FOUND[/b][/red]\n\n"

        else:
            sig_data = result[0]
            cert_info = (
                f"[b]Trust Status:[/b]  {sig_data.get('Trust Status')}\n\n"
                f"[b]Signing Time:[/b]  {sig_data.get('Signing time')}\n"
                f"[b]Serial Number:[/b] {sig_data.get('Serial Number')}\n"
                f"[b]Issuer:[/b]        {sig_data.get('Issuer')}\n\n"

                f"[b]Countersigner Signing time:[/b]  {sig_data.get('Countersigner Signing time')}\n"
                f"[b]Countersigner Serial Number:[/b] {sig_data.get('Countersigner Serial Number')}\n"
                f"[b]Countersigner Issuer:[/b]        {sig_data.get('Countersigner Issuer')}\n"
            )

        cert_label.update(cert_info)

    def update_general(self):
        self.inspector.get_general_info()
        general_label = self.query_one("#general-info", Label)
        general_data = self.inspector.result["general"]

        info_text = (
            f"[b]MD5:[/b]               {general_data['MD5']}\n"
            f"[b]SHA-256:[/b]           {general_data['SHA-256']}\n"
            f"[b]Imphash:[/b]           {general_data['Imphash']}\n\n"
            f"[b]Filename:[/b]          {general_data['Filename']}\n"
            f"[b]File Size:[/b]         {general_data['File Size (Bytes)']:,} Bytes\n"
            f"[b]e_lfanew Offset:[/b]   {general_data['e_lfanew Offset (Bytes)']} Bytes\n"
            f"[b]Machine:[/b]           {general_data['Machine']}\n"
            f"[b]Compile Time:[/b]      {general_data['Compile Time']}\n"
            f"[b]Entry Point (RVA):[/b] {general_data['Entry Point (RVA)']}\n"
            f"[b]Image Base:[/b]        {general_data['Image Base']}\n"
            f"[b]Size in RAM:[/b]       {general_data['Size in RAM (Bytes)']:,} Bytes\n"
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

    app = InspectorApp(inspector_backend)
    app.run()
