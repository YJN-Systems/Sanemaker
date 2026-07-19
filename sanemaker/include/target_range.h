#pragma once

#include <cstdint>
#include <vector>
#include <shared_mutex>

#include <metadata.h>

struct TargetFieldAccessHit {
	uint64_t field_index;

	// Relative to the beginning of the field.
	// begin inclusive, end exclusive.
	Range range;
};

struct TargetRangeHit {
	std::shared_ptr<const TargetInfo> target;
	uint64_t object_begin;
	uint64_t object_offset;
	std::vector<TargetFieldAccessHit> fields;
};

class TargetRangeSet {
    public:
	bool add(uint64_t begin, std::shared_ptr<const TargetInfo> target);
	bool remove_exact(uint64_t begin);

	bool contains(uint64_t addr) const;

	/*
	 * Returns every tagged object intersecting [addr, addr + size). A zero size is
	 * treated as a one-byte probe. Each result contains only the intersected
	 * portions of fields, expressed relative to each field's beginning.
	 */
	std::vector<TargetRangeHit> lookup(uint64_t addr, uint64_t size) const;

    private:
	struct TargetRange {
		uint64_t begin;
		uint64_t end;
		std::shared_ptr<const TargetInfo> target;
	};

	mutable std::shared_mutex mutex_;

	/*
	 * Active tagged-object ranges. Ranges must be non-empty and non-overlapping.
	 * The vector is currently unsorted, so lookup and insertion are linear.
	 */
	std::vector<TargetRange> ranges_;
};
