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

        yield Footer()

    def on_mount(self) -> None:
        sec_table = self.query_one("#sections-table", DataTable)
        sec_table.add_columns("Section Name", "Entropy", "Size")
        sections = self.inspector.get_sections_entropy()
        sec_table.add_rows(sections)

        general_label = self.query_one("#general-info", Label)
        md5_hash = self.inspector.calculate_md5()
        sha256_hash = self.inspector.calculate_sha256()
        info_text = (
            f"[b]MD5:[/b]\n{md5_hash}\n\n"
            f"[b]SHA-256:[/b]\n{sha256_hash}\n"
        )
        general_label.update(info_text)


        imp_table = self.query_one("#imports-table", DataTable)
        imp_table.add_columns("Function Name", "Thunk Offset")

        if self.iat_data:
            first_dll = list(self.iat_data.keys())[0]
            self.update_functions_view(first_dll)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        switcher = self.query_one(ContentSwitcher)
        self.query_one("#btn-entropy", Button).variant = "default"
        self.query_one("#btn-iat", Button).variant = "default"

        if event.button.id == "btn-entropy":
            event.button.variant = "primary"
            switcher.current = "pane-entropy"
        elif event.button.id == "btn-iat":
            event.button.variant = "primary"
            switcher.current = "pane-iat"

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


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <executable>")
        sys.exit(1)

    inspector_backend = Inspector(sys.argv[1])
    if not inspector_backend.load_file():
        print("Unable to read executable")
        sys.exit(1)

    app = SimpleInspectorUI(inspector_backend)
    app.run()
