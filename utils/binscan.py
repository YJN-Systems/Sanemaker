#!/usr/bin/env python3
import argparse
import json
import struct
from dataclasses import dataclass
from typing import BinaryIO, Optional

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


U64 = struct.Struct("<Q")


def read_u64(buf: bytes, off: int) -> int:
    return U64.unpack_from(buf, off)[0]


def hex_addr(x: int) -> str:
    return f"0x{x:x}"


def load_combine_patterns(path: str) -> list[str]:
    patterns = []

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            # Support both full-line and trailing comments.
            line = line.split("#", 1)[0].strip()

            if line:
                patterns.append(line)

    if not patterns:
        raise RuntimeError(
            f"Combine file {path!r} contains no function-name patterns"
        )

    return patterns


@dataclass
class Target:
    id: int
    addr: int
    hash: str
    name: str
    size: int
    fields: list[dict]


class BinScan:
    def __init__(self, path: str):
        self.path = path
        self.f: BinaryIO = open(path, "rb")
        self.elf = ELFFile(self.f)
        self.is_little = self.elf.little_endian

        if not self.is_little:
            raise RuntimeError("Only little-endian ELF files are supported for now")

        if self.elf.elfclass != 64:
            raise RuntimeError("Only ELF64 files are supported for now")

        self.targets: list[Target] = []
        self.targets_by_addr: dict[int, Target] = {}
        self.target_id_by_hash: dict[str, int] = {}

    def close(self) -> None:
        self.f.close()

    def section(self, name: str):
        return self.elf.get_section_by_name(name)

    def va_to_file_offset(self, va: int) -> int:
        for seg in self.elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue

            start = seg["p_vaddr"]
            mem_end = start + seg["p_memsz"]
            file_end = start + seg["p_filesz"]

            if start <= va < mem_end:
                if va >= file_end:
                    raise RuntimeError(f"VA {hex_addr(va)} is in BSS/no-file area")
                return seg["p_offset"] + (va - start)

        raise RuntimeError(f"VA {hex_addr(va)} is not mapped by a PT_LOAD segment")

    def read_va(self, va: int, size: int) -> bytes:
        off = self.va_to_file_offset(va)
        old = self.f.tell()
        self.f.seek(off)
        data = self.f.read(size)
        self.f.seek(old)

        if len(data) != size:
            raise RuntimeError(f"Short read at VA {hex_addr(va)}")

        return data

    def read_cstr(self, va: int) -> str:
        off = self.va_to_file_offset(va)
        old = self.f.tell()
        self.f.seek(off)

        out = bytearray()
        while True:
            b = self.f.read(1)
            if not b or b == b"\0":
                break
            out += b

        self.f.seek(old)
        return out.decode("utf-8", errors="replace")

    def symbol_addr(self, name: str) -> Optional[int]:
        for sec in self.elf.iter_sections():
            if not isinstance(sec, SymbolTableSection):
                continue

            for sym in sec.iter_symbols():
                if sym.name == name:
                    return sym["st_value"]

        return None

    def parse_combine_ranges(self, patterns: list[str]) -> list[dict]:
        """
        Return ranges for defined STT_FUNC symbols whose names contain at
        least one configured pattern.

        Ranges are represented as half-open intervals:

            begin <= pc < begin + size
        """
        ranges_by_location = {}

        for sec in self.elf.iter_sections():
            if not isinstance(sec, SymbolTableSection):
                continue

            for sym in sec.iter_symbols():
                if sym["st_info"]["type"] != "STT_FUNC":
                    continue

                # Ignore undefined/imported functions. They do not describe
                # code ranges inside this ELF file.
                if sym["st_shndx"] == "SHN_UNDEF":
                    continue

                name = sym.name
                begin = int(sym["st_value"])
                size = int(sym["st_size"])

                if not name or size <= 0:
                    continue

                if not any(pattern in name for pattern in patterns):
                    continue

                # The same function may appear in both .symtab and .dynsym.
                # Deduplicate by its actual address range.
                key = (begin, size)

                previous = ranges_by_location.get(key)

                # Prefer the shorter/simpler name when aliases describe the
                # exact same range. This choice only affects display output.
                if previous is None or len(name) < len(previous["name"]):
                    ranges_by_location[key] = {
                        "name": name,
                        "begin": hex_addr(begin),
                        "size": size,
                    }

        ranges = list(ranges_by_location.values())

        ranges.sort(
            key=lambda item: (
                int(item["begin"], 0),
                item["size"],
                item["name"],
            )
        )

        return ranges

    def section_addr_range(self, name: str) -> Optional[tuple[int, int]]:
        start = self.symbol_addr(f"__start_{name}")
        stop = self.symbol_addr(f"__stop_{name}")

        if start is not None and stop is not None:
            return start, stop

        s = self.section(name)
        if not s:
            return None

        return s["sh_addr"], s["sh_addr"] + s["sh_size"]

    def read_range(self, start: int, stop: int) -> bytes:
        if stop < start:
            raise RuntimeError(f"Invalid range {hex_addr(start)}..{hex_addr(stop)}")
        return self.read_va(start, stop - start)

    def executable_code_sections(self) -> list[dict]:
        out = []

        for sec in self.elf.iter_sections():
            flags = sec["sh_flags"]

            # SHF_ALLOC | SHF_EXECINSTR
            if not (flags & 0x2) or not (flags & 0x4):
                continue

            start = sec["sh_addr"]
            size = sec["sh_size"]

            if size == 0:
                continue

            out.append({
                "name": sec.name,
                "start": hex_addr(start),
                "stop": hex_addr(start + size),
                "size": size,
            })

        return out

    def parse_targets(self) -> list[dict]:
        rng = self.section_addr_range("spslr_targets")
        if not rng:
            return []

        start, stop = rng
        data = self.read_range(start, stop)

        # struct spslr_target:
        #   char hash[16]
        #   const char *name
        #   const struct spslr_target_layout *layout
        rec_size = 32

        if len(data) % rec_size != 0:
            raise RuntimeError("spslr_targets size is not a multiple of 32")

        targets = []

        for i in range(0, len(data), rec_size):
            addr = start + i
            h = data[i:i + 16].hex()
            name_ptr = read_u64(data, i + 16)
            layout_ptr = read_u64(data, i + 24)

            layout = self.read_va(layout_ptr, 24)
            size = read_u64(layout, 0)
            field_cnt = read_u64(layout, 8)
            fields_ptr = read_u64(layout, 16)

            field_data = self.read_va(fields_ptr, field_cnt * 40)
            fields = []

            for j in range(field_cnt):
                p = j * 40
                field_name_ptr = read_u64(field_data, p)
                fields.append({
                    "id": j,
                    "name": self.read_cstr(field_name_ptr),
                    "size": read_u64(field_data, p + 8),
                    "offset": read_u64(field_data, p + 16),
                    "alignment": read_u64(field_data, p + 24),
                    "flags": read_u64(field_data, p + 32),
                })

            target = Target(
                id=len(targets),
                addr=addr,
                hash=h,
                name=self.read_cstr(name_ptr),
                size=size,
                fields=fields,
            )

            self.targets.append(target)
            self.targets_by_addr[target.addr] = target
            self.target_id_by_hash[target.hash] = target.id

            targets.append({
                "id": target.id,
                "addr": hex_addr(target.addr),
                "hash": target.hash,
                "name": target.name,
                "size": target.size,
                "fields": target.fields,
            })

        return targets

    def target_id_from_target_addr(self, addr: int) -> int:
        target = self.targets_by_addr.get(addr)
        if not target:
            raise RuntimeError(f"Target ref points to unknown target {hex_addr(addr)}")

        mapped = self.target_id_by_hash.get(target.hash)
        if mapped is None:
            raise RuntimeError(f"Target hash not in global map: {target.hash}")

        return mapped

    def parse_unit_target_map(self, target_cnt: int, target_refs_ptr: int) -> list[int]:
        refs = self.read_va(target_refs_ptr, target_cnt * 8)
        out = []

        for i in range(target_cnt):
            target_addr = read_u64(refs, i * 8)
            out.append(self.target_id_from_target_addr(target_addr))

        return out

    def parse_dpins(self, unit_target_map: list[int], dpin_cnt: int, dpins_ptr: int) -> list[dict]:
        if dpin_cnt == 0:
            return []

        data = self.read_va(dpins_ptr, dpin_cnt * 16)
        out = []

        for i in range(dpin_cnt):
            p = i * 16
            addr = read_u64(data, p)
            local_target = read_u64(data, p + 8)

            if local_target >= len(unit_target_map):
                raise RuntimeError(f"dpin local target index out of range: {local_target}")

            out.append({
                "addr": hex_addr(addr),
                "target_id": unit_target_map[local_target],
            })

        return out

    def parse_ipins(self, unit_target_map: list[int], ipin_cnt: int, ipins_ptr: int) -> list[dict]:
        if ipin_cnt == 0:
            return []

        data = self.read_va(ipins_ptr, ipin_cnt * 24)
        out = []

        for i in range(ipin_cnt):
            p = i * 24
            addr = read_u64(data, p)
            size = read_u64(data, p + 8)
            expr_ptr = read_u64(data, p + 16)

            expr = self.read_va(expr_ptr, 16)
            local_target = read_u64(expr, 0)
            field_idx = read_u64(expr, 8)

            if local_target >= len(unit_target_map):
                raise RuntimeError(f"ipin local target index out of range: {local_target}")

            out.append({
                "addr": hex_addr(addr),
                "size": size,
                "target_id": unit_target_map[local_target],
                "field_idx": field_idx,
            })

        return out

    def entry_addr(self) -> int:
        return self.elf.header["e_entry"]

    def code_start(self) -> int:
        starts = []
        for sec in self.elf.iter_sections():
            flags = sec["sh_flags"]
            if (flags & 0x2) and (flags & 0x4) and sec["sh_size"] != 0:
                starts.append(sec["sh_addr"])

        if not starts:
            raise RuntimeError("No executable code sections found")

        return min(starts)

    def parse_traps(self) -> list[dict]:
        names = [
            "__sanemaker_target_tag_trap_incision",
            "__sanemaker_target_untag_trap_incision",
            "__sanemaker_finish_layout_trap_incision",
            "__sanemaker_fetch_trap_incision",
            "__sanemaker_signal_trap_incision",
            "__sanemaker_new_image_trap_incision",
            "__sanemaker_new_image_text_trap_incision",
            "__sanemaker_drop_image_trap_incision",
            "__sanemaker_drop_image_text_trap_incision",
        ]

        out = []
        for name in names:
            addr = self.symbol_addr(name)
            if addr is not None:
                out.append({
                    "name": name,
                    "addr": hex_addr(addr),
                })

        return out

    def parse_units(
        self,
        include_ipins: bool,
        include_dpins: bool,
    ) -> tuple[list[dict], list[dict], list[dict]]:
        rng = self.section_addr_range("spslr_units")
        if not rng:
            return [], [], []

        start, stop = rng
        data = self.read_range(start, stop)

        unit_size = 56

        if len(data) % unit_size != 0:
            raise RuntimeError(
                f"spslr_units size {len(data)} is not a multiple of expected unit size {unit_size}"
            )

        dpins = []
        ipins = []
        units = []

        for unit_id, idx in enumerate(range(0, len(data), unit_size)):
            uaddr = start + idx

            source_ptr = read_u64(data, idx)
            target_cnt = read_u64(data, idx + 8)
            target_refs_ptr = read_u64(data, idx + 16)
            ipin_cnt = read_u64(data, idx + 24)
            ipins_ptr = read_u64(data, idx + 32)
            dpin_cnt = read_u64(data, idx + 40)
            dpins_ptr = read_u64(data, idx + 48)

            source = self.read_cstr(source_ptr)
            unit_target_map = self.parse_unit_target_map(target_cnt, target_refs_ptr)

            unit_dpins = self.parse_dpins(unit_target_map, dpin_cnt, dpins_ptr) if include_dpins else []
            unit_ipins = self.parse_ipins(unit_target_map, ipin_cnt, ipins_ptr) if include_ipins else []

            for x in unit_dpins:
                x["unit"] = unit_id
            for x in unit_ipins:
                x["unit"] = unit_id

            dpins.extend(unit_dpins)
            ipins.extend(unit_ipins)

            unit_obj = {
                "id": unit_id,
                "addr": hex_addr(uaddr),
                "source": source,
                "target_ids": unit_target_map,
                "ipin_count": ipin_cnt,
                "dpin_count": dpin_cnt,
            }

            units.append(unit_obj)

        return units, dpins, ipins

    def scan(
        self,
        include_ipins: bool,
        include_dpins: bool,
        include_traps: bool,
        combine_patterns: Optional[list[str]] = None,
    ) -> dict:
        targets = self.parse_targets()
        units, dpins, ipins = self.parse_units(
            include_ipins,
            include_dpins,
        )

        result = {
            "binary": self.path,
            "entry": hex_addr(self.entry_addr()),
            "code_start": hex_addr(self.code_start()),
            "code": self.executable_code_sections(),
            "targets": targets,
            "units": units,
        }

        if include_dpins:
            result["dpins"] = dpins

        if include_ipins:
            result["ipins"] = ipins

        if include_traps:
            result["traps"] = self.parse_traps()

        if combine_patterns:
            result["combine_ranges"] = self.parse_combine_ranges(
                combine_patterns
            )

        return result

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Extract SPSLR metadata and Sanemaker incision symbols from an ELF binary."
    )
    ap.add_argument("binary")
    ap.add_argument("-o", "--output")
    ap.add_argument("--no-ipins", action="store_true", help="Do not dump ipins")
    ap.add_argument("--no-dpins", action="store_true", help="Do not dump dpins")
    ap.add_argument("--no-traps", action="store_true", help="Do not dump Sanemaker incision symbols")
    ap.add_argument("--combine", metavar="FILE",
        help=(
            "Text file containing function-name substrings whose code "
            "ranges should be emitted as combine_ranges"
        ),
    )

    args = ap.parse_args()

    try:
        combine_patterns = (
            load_combine_patterns(args.combine)
            if args.combine
            else None
        )
    except (OSError, RuntimeError) as exc:
        ap.error(str(exc))

    scanner = BinScan(args.binary)
    try:
        result = scanner.scan(
            include_ipins=not args.no_ipins,
            include_dpins=not args.no_dpins,
            include_traps=not args.no_traps,
            combine_patterns=combine_patterns,
        )
    finally:
        scanner.close()

    text = json.dumps(result, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
            f.write("\n")
    else:
        print(text)


if __name__ == "__main__":
    main()
