#include <code_range.h>

#include <algorithm>
#include <mutex>

void CodeRangeSet::add(uint64_t runtime_begin, uint64_t runtime_end,
		       uint64_t image_id, uint64_t runtime_base)
{
	if (runtime_begin >= runtime_end)
		return;

	std::unique_lock<std::shared_mutex> lock(mutex_);

	ranges_.push_back({
		runtime_begin,
		runtime_end,
		image_id,
		runtime_base,
	});

	std::sort(ranges_.begin(), ranges_.end(),
		  [](const CodeRange &a, const CodeRange &b) {
			  return a.runtime_begin < b.runtime_begin;
		  });
}

bool CodeRangeSet::remove(uint64_t runtime_begin, uint64_t runtime_end,
			  uint64_t image_id)
{
	if (runtime_begin >= runtime_end)
		return false;

	std::unique_lock<std::shared_mutex> lock(mutex_);

	bool removed = false;
	std::vector<CodeRange> updated;
	updated.reserve(ranges_.size() + 1);

	for (const CodeRange &range : ranges_) {
		/*
		 * Keep ranges belonging to other images, and ranges that do not
		 * overlap the interval being removed.
		 */
		if (range.image_id != image_id ||
		    runtime_end <= range.runtime_begin ||
		    runtime_begin >= range.runtime_end) {
			updated.push_back(range);
			continue;
		}

		removed = true;

		/*
		 * Preserve the part before the removed interval.
		 */
		if (range.runtime_begin < runtime_begin) {
			updated.push_back({
				range.runtime_begin,
				runtime_begin,
				range.image_id,
				range.runtime_base,
			});
		}

		/*
		 * Preserve the part after the removed interval.
		 */
		if (runtime_end < range.runtime_end) {
			updated.push_back({
				runtime_end,
				range.runtime_end,
				range.image_id,
				range.runtime_base,
			});
		}
	}

	if (!removed)
		return false;

	std::sort(updated.begin(), updated.end(),
		  [](const CodeRange &a, const CodeRange &b) {
			  return a.runtime_begin < b.runtime_begin;
		  });

	ranges_ = std::move(updated);
	return true;
}

void CodeRangeSet::remove_image(uint64_t image_id)
{
	std::unique_lock<std::shared_mutex> lock(mutex_);

	ranges_.erase(std::remove_if(ranges_.begin(), ranges_.end(),
				     [image_id](const CodeRange &r) {
					     return r.image_id == image_id;
				     }),
		      ranges_.end());
}

std::optional<CodeLocation> CodeRangeSet::lookup(uint64_t runtime_pc) const
{
	std::shared_lock<std::shared_mutex> lock(mutex_);

	auto it = std::upper_bound(ranges_.begin(), ranges_.end(), runtime_pc,
				   [](uint64_t value, const CodeRange &range) {
					   return value < range.runtime_begin;
				   });

	if (it == ranges_.begin())
		return std::nullopt;

	--it;

	if (runtime_pc >= it->runtime_end)
		return std::nullopt;

	return CodeLocation{
		it->image_id,
		runtime_pc - it->runtime_base,
	};
}

bool CodeRangeSet::contains(uint64_t runtime_pc) const
{
	return lookup(runtime_pc).has_value();
}
