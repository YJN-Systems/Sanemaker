#!/usr/bin/env python3
import json
import sys
from pathlib import Path


def parse_args(argv):
    opts = {}
    logs = []

    for arg in argv:
        if "=" in arg:
            k, v = arg.split("=", 1)
            opts[k] = v
        else:
            logs.append(arg)

    if "out" not in opts:
        raise SystemExit("missing required argument: out=...")

    if not logs:
        raise SystemExit("expected at least one per-pid log json file")

    return opts, logs


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def merge_ranges(ranges):
    rs = sorted((int(b), int(e)) for b, e in ranges)
    if not rs:
        return []

    merged = []
    cur_b, cur_e = rs[0]

    for b, e in rs[1:]:
        if b <= cur_e:
            cur_e = max(cur_e, e)
        else:
            merged.append([cur_b, cur_e])
            cur_b, cur_e = b, e

    merged.append([cur_b, cur_e])
    return merged


def normalize_pc(pc):
    if isinstance(pc, str):
        return int(pc, 0)
    return int(pc)


def pc_json(pc):
    return f"0x{pc:x}"


def collect_targets(logs):
    by_key = {}
    out = []
    next_id = 0
    old_to_new = []

    for data in logs:
        mapping = {}

        for t in data.get("targets", []):
            key = t.get("hash", json.dumps(t, sort_keys=True))

            if key not in by_key:
                new_t = dict(t)
                new_t["id"] = next_id
                by_key[key] = next_id
                out.append(new_t)
                next_id += 1

            mapping[int(t["id"])] = by_key[key]

        old_to_new.append(mapping)

    return out, old_to_new


def add_access(dst, item, target_map):
    old_tid = int(item["target"])
    new_tid = target_map.get(old_tid, old_tid)
    fid = int(item["field"])

    key = (new_tid, fid)
    dst.setdefault(key, []).extend(item.get("ranges", []))


def main(argv):
    opts, paths = parse_args(argv)
    logs = [load_json(p) for p in paths]

    targets, target_maps = collect_targets(logs)

    # (image, pc) -> {"before": {(target, field): ranges}, "after": ...}
    memops = {}

    for data, target_map in zip(logs, target_maps):
        for image_entry in data.get("accesses", []):
            image = image_entry.get("image", "<unknown-image>")

            for entry in image_entry.get("memops", []):
                pc = normalize_pc(entry["pc"])
                key = (image, pc)

                dst = memops.setdefault(key, {"before": {}, "after": {}})

                for item in entry.get("before", []):
                    add_access(dst["before"], item, target_map)

                for item in entry.get("after", []):
                    add_access(dst["after"], item, target_map)

    accesses_by_image = {}

    for (image, pc), phases in sorted(memops.items()):
        out_entry = {
            "pc": pc_json(pc),
            "before": [],
            "after": [],
        }

        for phase in ("before", "after"):
            for (target, field), ranges in sorted(phases[phase].items()):
                out_entry[phase].append({
                    "target": target,
                    "field": field,
                    "ranges": merge_ranges(ranges),
                })

        accesses_by_image.setdefault(image, []).append(out_entry)

    merged = {
        "targets": targets,
        "accesses": [
            {
                "image": image,
                "memops": memops,
            }
            for image, memops in sorted(accesses_by_image.items())
        ],
    }

    out_path = Path(opts["out"])
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main(sys.argv[1:])
