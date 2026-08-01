# Shell component

`shell.c` is Raven code, built by `scripts/provision-controls.py` into `raven-shell.dll` on the
public Windows headers. It supplies what the system libraries of the guest cannot answer on their own:

- the common file dialogs: `GetOpenFileNameW`, `GetSaveFileNameW` and the `IFileOpenDialog` /
  `IFileSaveDialog` objects (with `IFileDialogCustomize` check boxes), all driven by one dialog
  template assembled in memory and shown by the dialog manager of the user32 component;
- shell items (`IShellItem`, `IShellItemArray`) and `SHCreateItemFromParsingName`;
- the class registry behind `CoCreateInstance`, which creates the file dialog classes.

Its exports replace the same-named exports of `comdlg32.dll`, `ole32.dll` and `shell32.dll` for programs
that import those libraries. Setting `RAVEN_TRACE_SHELL` to a guest file path appends one line per
interface request and dialog call to that file.
