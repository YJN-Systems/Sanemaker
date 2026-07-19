#pragma once
#include <cstdint>
#include <optional>
#include <vector>
#include <shared_mutex>

struct CodeLocation {
	uint64_t image_id;
	uint64_t image_pc;
};

struct CodeRange {
	uint64_t runtime_begin;
	uint64_t runtime_end;
	uint64_t image_id;
	uint64_t runtime_base;
};

class CodeRangeSet {
    public:
	void add(uint64_t runtime_begin, uint64_t runtime_end,
		 uint64_t image_id, uint64_t runtime_base);

	bool remove(uint64_t runtime_begin, uint64_t runtime_end,
		    uint64_t image_id);

	void remove_image(uint64_t image_id);

	std::optional<CodeLocation> lookup(uint64_t runtime_pc) const;
	bool contains(uint64_t runtime_pc) const;

    private:
	mutable std::shared_mutex mutex_;

	/*
	 * Runtime code mappings sorted by runtime_begin. lookup() assumes mappings do
	 * not overlap in a way that makes the immediately preceding range ambiguous.
	 */
	std::vector<CodeRange> ranges_;
};
