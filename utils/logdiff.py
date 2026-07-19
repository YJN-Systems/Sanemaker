#!/usr/bin/env python3
import json
import sys
from dataclasses import dataclass


def parse_args(argv):
    opts = {}
    logs = []

    for arg in argv:
        if "=" in arg:
            key, value = arg.split("=", 1)
            opts[key] = value
        else:
            logs.append(arg)

    for key in ("binscan", "missing", "mismatches"):
        if key not in opts:
            raise SystemExit(
                f"missing required argument: {key}=..."
            )

    if len(logs) < 2:
        raise SystemExit(
            "expected at least two log json files"
        )

    return opts, logs


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_int(value, description):
    try:
        if isinstance(value, str):
            return int(value, 0)

        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"invalid {description}: {value!r}"
        ) from exc


@dataclass(frozen=True, order=True)
class FieldAccess:
    """
    One field and all accessed byte ranges within that field.

    Ranges use half-open intervals:

        begin <= offset < end
    """

    name: str
    ranges: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class CombineRange:
    name: str
    begin: int
    size: int

    @property
    def end(self):
        return self.begin + self.size

    def contains(self, pc):
        return self.begin <= pc < self.end


def merge_ranges(ranges):
    """
    Merge overlapping and adjacent half-open ranges.

    Examples:

        (0, 8), (8, 16), (16, 24)
            -> (0, 24)

        (0, 12), (8, 20)
            -> (0, 20)

        (0, 8), (16, 24)
            -> (0, 8), (16, 24)
    """
    ranges = sorted(ranges)

    merged = []

    for begin, end in ranges:
        if begin < 0:
            raise ValueError(
                f"negative field-access range begin: {begin}"
            )

        if end < begin:
            raise ValueError(
                f"field-access range ends before it begins: "
                f"{begin}-{end}"
            )

        if not merged:
            merged.append([begin, end])
            continue

        previous_begin, previous_end = merged[-1]

        # Merge overlapping ranges and ranges that touch exactly.
        if begin <= previous_end:
            merged[-1][1] = max(previous_end, end)
        else:
            merged.append([begin, end])

    return tuple(
        (begin, end)
        for begin, end in merged
    )


def normalize_accesses(accesses):
    """
    Combine all FieldAccess objects with the same field name and merge
    their overlapping or adjacent ranges.

    The returned tuple is sorted and hashable, so it can be compared
    directly between logs and placed in sets.
    """
    ranges_by_name = {}

    for access in accesses:
        ranges_by_name.setdefault(
            access.name,
            [],
        ).extend(access.ranges)

    normalized = []

    for name, ranges in ranges_by_name.items():
        normalized.append(
            FieldAccess(
                name=name,
                ranges=merge_ranges(ranges),
            )
        )

    return tuple(sorted(normalized))


def format_access(access):
    ranges_text = ",".join(
        f"{begin}-{end}"
        for begin, end in access.ranges
    )

    return f"{access.name}[{ranges_text}]"


def fmt_fields(accesses):
    if not accesses:
        return "[<no-fields>]"

    return "[" + ", ".join(
        format_access(access)
        for access in sorted(accesses)
    ) + "]"


def load_combine_ranges(binscan):
    raw_ranges = binscan.get(
        "combine_ranges",
        [],
    )

    if not isinstance(raw_ranges, list):
        raise ValueError(
            "binscan 'combine_ranges' must be a list"
        )

    ranges = []

    for index, item in enumerate(raw_ranges):
        if not isinstance(item, dict):
            raise ValueError(
                f"combine_ranges entry {index} is not an object"
            )

        try:
            name = str(item["name"])
            begin = parse_int(
                item["begin"],
                f"begin of combine range {index}",
            )
            size = parse_int(
                item["size"],
                f"size of combine range {index}",
            )
        except KeyError as exc:
            raise ValueError(
                f"combine_ranges entry {index} is missing "
                f"{exc.args[0]!r}"
            ) from exc

        if begin < 0:
            raise ValueError(
                f"combine range {name!r} has a negative begin"
            )

        if size <= 0:
            raise ValueError(
                f"combine range {name!r} must have a positive size"
            )

        ranges.append(
            CombineRange(
                name=name,
                begin=begin,
                size=size,
            )
        )

    ranges.sort(
        key=lambda item: (
            item.begin,
            item.end,
            item.name,
        )
    )

    # A PC must not belong to multiple combine ranges.
    for previous, current in zip(
        ranges,
        ranges[1:],
    ):
        if current.begin < previous.end:
            raise ValueError(
                "overlapping combine ranges in binscan JSON: "
                f"{previous.name}"
                f"[0x{previous.begin:x}-0x{previous.end:x}) and "
                f"{current.name}"
                f"[0x{current.begin:x}-0x{current.end:x})"
            )

    return ranges


def loc_str(loc):
    image, location = loc

    if isinstance(location, CombineRange):
        return (
            f"{image}:{location.name}"
            f"[0x{location.begin:x}-0x{location.end:x})"
        )

    return f"{image}:0x{location:x}"


def loc_sort_key(loc):
    image, location = loc

    if isinstance(location, CombineRange):
        return (
            image,
            location.begin,
            0,
            location.name,
            location.size,
        )

    return (
        image,
        location,
        1,
        "",
        0,
    )


def build_binscan_names(binscan):
    by_hash = {}

    for target in binscan.get("targets", []):
        target_hash = target["hash"]
        target_name = target.get(
            "name",
            target_hash,
        )

        fields = []

        for field in target.get("fields", []):
            field_name = field.get(
                "name",
                field.get("id"),
            )

            fields.append(
                f"{target_name}.{field_name}"
            )

        by_hash[target_hash] = fields

    return by_hash


def load_log(path, binscan_names):
    data = load_json(path)

    target_hash_by_id = {}

    for target in data.get("targets", []):
        target_hash_by_id[
            int(target["id"])
        ] = target["hash"]

    def decode_accesses(items):
        accesses = []

        for item in items:
            target_id = int(item["target"])
            field_id = int(item["field"])

            target_hash = target_hash_by_id.get(
                target_id
            )

            if target_hash is None:
                name = (
                    f"<unknown-target:{target_id}>"
                    f".<field:{field_id}>"
                )
            else:
                fields = binscan_names.get(
                    target_hash
                )

                if (
                    fields is None
                    or field_id < 0
                    or field_id >= len(fields)
                ):
                    name = (
                        f"<target:{target_hash}>"
                        f".<field:{field_id}>"
                    )
                else:
                    name = fields[field_id]

            ranges = []

            for range_index, raw_range in enumerate(
                item.get("ranges", [])
            ):
                if (
                    not isinstance(raw_range, (list, tuple))
                    or len(raw_range) != 2
                ):
                    raise ValueError(
                        f"invalid range {range_index} for "
                        f"{name!r}: {raw_range!r}"
                    )

                begin = parse_int(
                    raw_range[0],
                    f"range begin for {name}",
                )

                end = parse_int(
                    raw_range[1],
                    f"range end for {name}",
                )

                ranges.append(
                    (begin, end)
                )

            accesses.append(
                FieldAccess(
                    name=name,
                    ranges=tuple(ranges),
                )
            )

        return normalize_accesses(accesses)

    accesses = {}

    for image_entry in data.get("accesses", []):
        image = image_entry.get(
            "image",
            "<unknown-image>",
        )

        for entry in image_entry.get(
            "memops",
            [],
        ):
            pc = parse_int(
                entry["pc"],
                "program counter",
            )

            key = (image, pc)

            decoded = {
                "before": decode_accesses(
                    entry.get("before", [])
                ),
                "after": decode_accesses(
                    entry.get("after", [])
                ),
            }

            # Merge repeated records for the same image and PC instead of
            # replacing an earlier record.
            if key not in accesses:
                accesses[key] = decoded
            else:
                accesses[key] = {
                    phase: normalize_accesses(
                        accesses[key][phase]
                        + decoded[phase]
                    )
                    for phase in (
                        "before",
                        "after",
                    )
                }

    return accesses


def find_combine_range(pc, ranges):
    """
    Return the combine range containing pc, or None.

    The range list must be sorted by begin address.
    """
    for combine_range in ranges:
        if combine_range.contains(pc):
            return combine_range

        if combine_range.begin > pc:
            break

    return None


def apply_combine_ranges(accesses, ranges):
    if not ranges:
        return accesses

    combined = {}

    for (image, pc), phases in accesses.items():
        combine_range = find_combine_range(
            pc,
            ranges,
        )

        location = (
            combine_range
            if combine_range is not None
            else pc
        )

        key = (image, location)

        if key not in combined:
            combined[key] = {
                "before": [],
                "after": [],
            }

        combined[key]["before"].extend(
            phases["before"]
        )

        combined[key]["after"].extend(
            phases["after"]
        )

    # Normalize after all PCs in a function range have been collected.
    # This is where adjacent accesses from different PCs are merged.
    return {
        key: {
            "before": normalize_accesses(
                phases["before"]
            ),
            "after": normalize_accesses(
                phases["after"]
            ),
        }
        for key, phases in combined.items()
    }


def write_mismatch(
    out,
    heading,
    loc,
    present,
    logs,
    phase,
):
    """
    Print accesses common to every present log, followed by accesses
    unique to each log relative to that common set.
    """
    accesses_by_log = {
        path: set(logs[path][loc][phase])
        for path in present
    }

    common = set.intersection(
        *accesses_by_log.values()
    )

    out.write(
        f"{heading} mismatch at pc {loc_str(loc)}\n"
    )

    out.write(
        f"  common: {fmt_fields(common)}\n"
    )

    for path in present:
        additional = (
            accesses_by_log[path] - common
        )

        if additional:
            out.write(
                f"  {path} additional: "
                f"{fmt_fields(additional)}\n"
            )

    out.write("\n")


def main(argv):
    opts, log_paths = parse_args(argv)

    binscan = load_json(
        opts["binscan"]
    )

    binscan_names = build_binscan_names(
        binscan
    )

    try:
        combine_ranges = load_combine_ranges(
            binscan
        )
    except ValueError as exc:
        raise SystemExit(
            f"invalid combine ranges in binscan JSON: {exc}"
        ) from exc

    try:
        logs = {
            path: apply_combine_ranges(
                load_log(
                    path,
                    binscan_names,
                ),
                combine_ranges,
            )
            for path in log_paths
        }
    except ValueError as exc:
        raise SystemExit(
            f"invalid log data: {exc}"
        ) from exc

    all_locs = set()

    for log in logs.values():
        all_locs.update(
            log.keys()
        )

    with open(
        opts["missing"],
        "w",
        encoding="utf-8",
    ) as out:
        for loc in sorted(
            all_locs,
            key=loc_sort_key,
        ):
            missing = [
                path
                for path in log_paths
                if loc not in logs[path]
            ]

            if missing:
                out.write(
                    f"The location {loc_str(loc)} is missing in "
                    f"[{', '.join(missing)}]\n"
                )

    with open(
        opts["mismatches"],
        "w",
        encoding="utf-8",
    ) as out:
        for loc in sorted(
            all_locs,
            key=loc_sort_key,
        ):
            present = [
                path
                for path in log_paths
                if loc in logs[path]
            ]

            if len(present) < 2:
                continue

            before_variants = {
                logs[path][loc]["before"]
                for path in present
            }

            after_variants = {
                logs[path][loc]["after"]
                for path in present
            }

            if len(before_variants) > 1:
                write_mismatch(
                    out,
                    "Pre-patch",
                    loc,
                    present,
                    logs,
                    "before",
                )

            if len(after_variants) > 1:
                write_mismatch(
                    out,
                    "Post-patch",
                    loc,
                    present,
                    logs,
                    "after",
                )


if __name__ == "__main__":
    main(sys.argv[1:])
