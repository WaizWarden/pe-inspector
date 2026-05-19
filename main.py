import sys
from textual.app import App, ComposeResult
from textual.containers import ScrollableContainer, Horizontal
from textual.widgets import Footer, DataTable, Label, Button, ContentSwitcher, ListView, ListItem
from inspector import Inspector
from CSS import STYLES


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
            with ScrollableContainer(id="pane-entropy", classes="pane"):
                yield Label("[b]PE SECTIONS[/b]\n")
                yield DataTable(id="sections-table")

            with Horizontal(id="pane-iat", classes="pane"):
                with Horizontal(id="split-container"):
                    with ScrollableContainer(id="left-panel", classes="sub-panel"):
                        yield Label("[b]Library Modules[/b]\n")
                        self.iat_data = self.inspector.get_iat_data()

                        list_items = []
                        for index, dll in enumerate(self.iat_data.keys()):
                            list_items.append(ListItem(Label(dll), id=f"dll-{index}"))

                        yield ListView(*list_items, id="dll-list")

                    with ScrollableContainer(id="right-panel", classes="sub-panel"):
                        yield Label("[b]Imported Functions[/b]\n")
                        yield DataTable(id="imports-table")

        yield Footer()

    def on_mount(self) -> None:
        sec_table = self.query_one("#sections-table", DataTable)
        sec_table.add_columns("Section Name", "Entropy", "Size")
        sections = self.inspector.get_sections_entropy()
        sec_table.add_rows(sections)

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
        sys.exit(1)

    inspector_backend = Inspector(sys.argv[1])
    if not inspector_backend.load_file():
        sys.exit(1)

    app = SimpleInspectorUI(inspector_backend)
    app.run()