STYLES = """
Screen {
    layout: grid;
    grid-size: 1 2;
    grid-rows: auto 1fr;
}
#top-bar {
    column-span: 2;
    height: 3;
    background: $boost;
    border-bottom: solid $accent;
    padding: 0 2;
    content-align: left middle;
}
ContentSwitcher {
    height: 1fr;
}
.pane {
    border: round $primary;
    padding: 1;
    margin: 1;
    height: 100%;
}
#split-container {
    layout: horizontal;
    height: 100%;
}
.sub-panel {
    width: 1fr;
    height: 100%;
    border: solid $secondary;
    padding: 1;
}
#left-panel {
    width: 1fr;
}
#right-panel {
    width: 2fr;
}
"""