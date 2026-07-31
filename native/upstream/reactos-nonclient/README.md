# Nonclient rectangle calculation

`borders.inc` retains three unchanged functions and the original notice from
`win32ss/user/user32/windows/nonclient.c` at ReactOS revision
`32bb061415f813b6ced25ff91f4d258f33c5191f`. Function ranges and hashes are in
`provenance.json`. The source is LGPL-2.1-or-later; COPYING.LIB is preserved.

The host adapter binds metric reads to the owning DesktopObjects profile. Wide
rectangle intermediates are converted back to the 32-bit guest RECT modulo its
word width. No global USER state, hooks, NT drawing services or upstream window
owner is introduced. The default profile records the measured classic 96-DPI
Wine values for thirteen nonclient metrics. Display/theme/DPI synchronization and
the remaining metric indices are open.

This component calculates AdjustWindowRect and AdjustWindowRectEx only. Caption
rendering, menus, hit testing and standard window creation remain separate work.
Product distribution and combined-license review remain packaging gates.
