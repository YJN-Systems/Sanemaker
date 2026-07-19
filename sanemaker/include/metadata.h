#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <shared_mutex>

struct Range {
	uint64_t begin;
	uint64_t end; // exclusive
};

struct FieldRangeHit {
	/* This range is relative to the beginning of the field. */
	Range range;

	uint64_t field_index;
};

struct FieldInfo {
	std::string name;
	uint64_t offset;
	uint64_t size;
};

/*
 * Metadata for one target object type.
 *
 * fields contains immutable field identity, size, and original offsets.
 * current_offsets_ contains the active runtime layout, which may be replaced
 * by a FinishLayout trap while memory callbacks concurrently query it.
 */
struct TargetInfo {
	TargetInfo() = default;

	TargetInfo(const TargetInfo &) = delete;
	TargetInfo &operator=(const TargetInfo &) = delete;
	TargetInfo(TargetInfo &&) = delete;
	TargetInfo &operator=(TargetInfo &&) = delete;

	std::string hash;
	uint64_t size;
	std::vector<FieldInfo> fields;

	void reset_layout();
	bool set_current_layout(const std::vector<uint64_t> &offsets);
	std::vector<FieldRangeHit> fields_in_range(uint64_t offset,
						   uint64_t size) const;

    private:
	void rebuild_layout_indexes_unlocked();

	mutable std::shared_mutex layout_mutex_;

	// field index -> current runtime offset
	std::vector<uint64_t> current_offsets_;

	// Current runtime offset -> all field indices beginning there.
	std::map<uint64_t, std::set<uint64_t> > fields_by_offset_;

	/*
	 * For each distinct field end E, stores the earliest start offset among
	 * all non-empty fields ending at E or later. This suffix-minimum index
	 * lets fields_in_range() skip fields that must have ended before an access,
	 * while still handling overlapping and reordered fields.
	 */
	std::map<uint64_t, uint64_t> first_offset_by_end_;
};

enum class TrapKind {
	Tag,
	Untag,
	FinishLayout,
	Fetch,
	Signal,
	NewImage,
	NewImageText,
	DropImage,
	DropImageText,
};

struct TrapInfo {
	uint64_t image_pc;
	TrapKind kind;
};

class Metadata {
    public:
	bool load(const char *path);

	uint64_t code_start() const
	{
		return code_start_;
	}
	std::shared_ptr<const TargetInfo>
	target_by_hash(const std::string &hash) const;
	std::shared_ptr<TargetInfo> target_by_hash(const std::string &hash);

	const std::vector<Range> &code_ranges() const
	{
		return code_ranges_;
	}
	const std::unordered_map<uint64_t, TrapInfo> &traps_by_image_pc() const
	{
		return traps_by_image_pc_;
	}

    private:
	uint64_t code_start_ = 0;
	std::vector<Range> code_ranges_;
	std::unordered_map<std::string, std::shared_ptr<TargetInfo> > targets_;
	std::unordered_map<uint64_t, TrapInfo> traps_by_image_pc_;
};
