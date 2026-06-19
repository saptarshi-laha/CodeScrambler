"""Repoint PE data directories so everything keeps working after code moves.

When instructions are relocated into a new section, every structure that refers
to a code address by RVA or VA must be updated to the new location. This module
walks the directories that can point at code and rewrites them in place:

* TLS callback table (array of callback VAs)
* Export Address Table (array of function RVAs)
* x64 exception table ``.pdata`` (``RUNTIME_FUNCTION`` begin/end RVAs)
* x86 SAFESEH handler table in the Load Config directory

Each value is only changed when it actually moved, so binaries that do not use
a given feature are left untouched. Where a transform changes a function's size
(so its end address is no longer an instruction boundary) the end is
approximated from the new start plus the original span; this keeps unwind ranges
well-formed even if heavy transforms make them imprecise.
"""

from __future__ import annotations

import struct
from typing import Callable, Optional

import pefile

#: ``old_rva -> new_rva`` (or ``None`` when the RVA was not moved).
RvaRemap = Callable[[int], Optional[int]]


class Fidelity:
    """Rewrites code-referencing directories to their post-move addresses."""

    def __init__(self, pe: "pefile.PE", remap: RvaRemap, image_base: int, ptr_size: int) -> None:
        self.pe = pe
        self.remap = remap
        self.image_base = image_base
        self.ptr_size = ptr_size
        self.changes: list = []

    def retarget_all(self) -> None:
        self._retarget_tls()
        self._retarget_exports()
        self._retarget_exceptions()
        self._retarget_safeseh()

    # -- helpers ----------------------------------------------------------
    def _remap_rva(self, rva: int) -> Optional[int]:
        return self.remap(rva)

    def _write_pointer(self, rva: int, value: int) -> None:
        data = value.to_bytes(self.ptr_size, "little")
        self.pe.set_bytes_at_rva(rva, data)

    def _read_pointer(self, rva: int) -> int:
        data = self.pe.get_data(rva, self.ptr_size)
        return int.from_bytes(data, "little")

    # -- TLS --------------------------------------------------------------
    def _retarget_tls(self) -> None:
        if not hasattr(self.pe, "DIRECTORY_ENTRY_TLS"):
            return
        tls = self.pe.DIRECTORY_ENTRY_TLS.struct
        callbacks_va = tls.AddressOfCallBacks
        if not callbacks_va:
            return
        cursor = callbacks_va - self.image_base
        while True:
            callback_va = self._read_pointer(cursor)
            if callback_va == 0:
                break
            new_rva = self._remap_rva(callback_va - self.image_base)
            if new_rva is not None:
                self._write_pointer(cursor, self.image_base + new_rva)
                self.changes.append(("tls_callback", callback_va))
            cursor += self.ptr_size

    # -- exports ----------------------------------------------------------
    def _retarget_exports(self) -> None:
        if not hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            return
        export_dir = self.pe.DIRECTORY_ENTRY_EXPORT.struct
        funcs_rva = export_dir.AddressOfFunctions
        for i in range(export_dir.NumberOfFunctions):
            slot = funcs_rva + i * 4
            old_rva = self.pe.get_dword_at_rva(slot)
            if old_rva == 0:
                continue
            new_rva = self._remap_rva(old_rva)
            if new_rva is not None:
                self.pe.set_dword_at_rva(slot, new_rva)
                self.changes.append(("export", old_rva))

    # -- x64 exception table ---------------------------------------------
    def _retarget_exceptions(self) -> None:
        if not hasattr(self.pe, "DIRECTORY_ENTRY_EXCEPTION"):
            return
        for entry in self.pe.DIRECTORY_ENTRY_EXCEPTION:
            begin = entry.struct.BeginAddress
            end = entry.struct.EndAddress
            new_begin = self._remap_rva(begin)
            if new_begin is None:
                continue
            new_end = self._remap_rva(end)
            if new_end is None:
                new_end = new_begin + (end - begin)
            # RUNTIME_FUNCTION lives in .pdata; patch the raw bytes directly so
            # the change survives serialization (BeginAddress, EndAddress).
            offset = entry.struct.get_file_offset()
            self.pe.set_dword_at_offset(offset, new_begin)
            self.pe.set_dword_at_offset(offset + 4, new_end)
            self.changes.append(("pdata", begin))

    # -- x86 SAFESEH ------------------------------------------------------
    def _retarget_safeseh(self) -> None:
        if not hasattr(self.pe, "DIRECTORY_ENTRY_LOAD_CONFIG"):
            return
        cfg = self.pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
        table_va = getattr(cfg, "SEHandlerTable", 0)
        count = getattr(cfg, "SEHandlerCount", 0)
        if not table_va or not count:
            return
        base_rva = table_va - self.image_base
        for i in range(count):
            slot = base_rva + i * 4
            old_rva = self.pe.get_dword_at_rva(slot)
            new_rva = self._remap_rva(old_rva)
            if new_rva is not None:
                self.pe.set_dword_at_rva(slot, new_rva)
                self.changes.append(("safeseh", old_rva))
