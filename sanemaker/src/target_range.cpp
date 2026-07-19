#include <target_range.h>

#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <mutex>

bool TargetRangeSet::add(uint64_t begin,
			 std::shared_ptr<const TargetInfo> target)
{
	if (!target)
		return false;

	uint64_t size = target->size;
	if (size == 0)
		return false;

	uint64_t end = begin + size;
	if (end <= begin)
		return false;

	std::unique_lock<std::shared_mutex> lock(mutex_);

	for (const auto &r : ranges_) {
		if (begin < r.end && end > r.begin) {
			std::fprintf(stderr,
				     "sanemaker: overlapping target range "
				     "0x%016" PRIx64 "-0x%016" PRIx64
				     " overlaps 0x%016" PRIx64 "-0x%016" PRIx64
				     "\n",
				     begin, end, r.begin, r.end);
			return false;
		}
	}

	ranges_.push_back({ begin, end, std::move(target) });
	return true;
}

bool TargetRangeSet::remove_exact(uint64_t begin)
{
	std::unique_lock<std::shared_mutex> lock(mutex_);

	for (auto it = ranges_.begin(); it != ranges_.end(); ++it) {
		if (it->begin == begin) {
			ranges_.erase(it);
			return true;
		}
	}

	return false;
}

bool TargetRangeSet::contains(uint64_t addr) const
{
	return !lookup(addr, 0).empty();
}

std::vector<TargetRangeHit> TargetRangeSet::lookup(uint64_t addr,
						   uint64_t size) const
{
	std::shared_lock<std::shared_mutex> lock(mutex_);

	std::vector<TargetRangeHit> out;

	uint64_t end = addr + size;
	if (size == 0)
		end = addr + 1;

	if (end < addr)
		end = UINT64_MAX;

	for (const auto &r : ranges_) {
		if (addr >= r.end || end <= r.begin)
			continue;

		uint64_t hit_begin = std::max(addr, r.begin);
		uint64_t hit_end = std::min(end, r.end);
		uint64_t object_offset = hit_begin - r.begin;
		uint64_t object_size = hit_end - hit_begin;

		TargetRangeHit hit{};
		hit.target = r.target;
		hit.object_begin = r.begin;
		hit.object_offset = object_offset;

		for (const FieldRangeHit &field_hit :
		     r.target->fields_in_range(object_offset, object_size)) {
			hit.fields.push_back({
				field_hit.field_index,
				field_hit.range,
			});
		}

		out.push_back(std::move(hit));
	}

	return out;
}
