#include <access_log.h>

#include <algorithm>
#include <cinttypes>

#include <rapidjson/document.h>
#include <rapidjson/filewritestream.h>
#include <rapidjson/prettywriter.h>

static void insert_access_range(std::vector<AccessRange> &ranges,
				AccessRange range)
{
	if (range.begin >= range.end)
		return;

	/*
	 * Find the first range that is not strictly before the new range.
	 *
	 * Using '<' rather than '<=' means that a range ending exactly at
	 * range.begin is considered touching and will therefore be merged.
	 *
	 * Since the ranges are sorted and non-overlapping, their end values
	 * are sorted as well.
	 */
	auto first = std::lower_bound(ranges.begin(), ranges.end(), range.begin,
				      [](const AccessRange &existing,
					 uint64_t begin) {
					      return existing.end < begin;
				      });

	/* Everything is before the new range. */
	if (first == ranges.end()) {
		ranges.push_back(range);
		return;
	}

	/* The new range is strictly before first, with a gap between them. */
	if (range.end < first->begin) {
		ranges.insert(first, range);
		return;
	}

	/* Common steady-state case: the access is already fully covered. */
	if (first->begin <= range.begin && range.end <= first->end)
		return;

	/* Merge first and every following touching/overlapping range. */
	range.begin = std::min(range.begin, first->begin);
	range.end = std::max(range.end, first->end);

	auto last = first + 1;
	while (last != ranges.end() && last->begin <= range.end) {
		range.end = std::max(range.end, last->end);
		++last;
	}

	*first = range;
	ranges.erase(first + 1, last);
}

uint64_t AccessLogger::target_index(const std::string &hash)
{
	auto it = target_by_hash_.find(hash);
	if (it != target_by_hash_.end())
		return it->second;

	uint64_t idx = target_by_hash_.size();
	target_by_hash_[hash] = idx;
	return idx;
}

void AccessLogger::register_image(uint64_t image_id, const std::string &name)
{
	std::lock_guard<std::mutex> guard{ lock_ };
	image_names_[image_id] = name;
}

void AccessLogger::log(uint64_t image_id, uint64_t pc,
		       const std::vector<TargetRangeHit> &hits,
		       bool after_patch)
{
	std::lock_guard<std::mutex> guard{ lock_ };

	auto &pc_log = logs_by_image_[image_id][pc];
	auto &accesses = after_patch ? pc_log.after_patch : pc_log.before_patch;

	for (const TargetRangeHit &target_hit : hits) {
		if (!target_hit.target)
			continue;

		uint64_t target = target_index(target_hit.target->hash);

		for (const TargetFieldAccessHit &field_hit :
		     target_hit.fields) {
			if (field_hit.range.begin >= field_hit.range.end)
				continue;

			auto &ranges =
				accesses[{ target, field_hit.field_index }];

			insert_access_range(ranges,
					    {
						    field_hit.range.begin,
						    field_hit.range.end,
					    });
		}
	}
}

static void
write_access_map(rapidjson::PrettyWriter<rapidjson::FileWriteStream> &w,
		 const AccessMap &accesses)
{
	w.StartArray();

	for (const auto &[key, ranges] : accesses) {
		w.StartObject();

		w.Key("target");
		w.Uint64(key.target);

		w.Key("field");
		w.Uint64(key.field);

		w.Key("ranges");
		w.StartArray();

		for (const AccessRange &range : ranges) {
			w.StartArray();
			w.Uint64(range.begin);
			w.Uint64(range.end);
			w.EndArray();
		}

		w.EndArray();
		w.EndObject();
	}

	w.EndArray();
}

bool AccessLogger::write(FILE *file) const
{
	if (!file) {
		std::fprintf(
			stderr,
			"sanemaker: AccessLogger::write received null FILE pointer\n");
		return false;
	}

	std::lock_guard<std::mutex> guard{ lock_ };

	char buffer[65536];
	rapidjson::FileWriteStream stream(file, buffer, sizeof(buffer));
	rapidjson::PrettyWriter<rapidjson::FileWriteStream> w(stream);

	w.StartObject();

	w.Key("targets");
	w.StartArray();

	for (const auto &[hash, id] : target_by_hash_) {
		w.StartObject();

		w.Key("id");
		w.Uint64(id);

		w.Key("hash");
		w.String(hash.c_str());

		w.EndObject();
	}

	w.EndArray();

	w.Key("accesses");
	w.StartArray();

	for (const auto &[image_id, logs] : logs_by_image_) {
		w.StartObject();

		w.Key("image");
		auto image_it = image_names_.find(image_id);
		if (image_it != image_names_.end()) {
			w.String(image_it->second.c_str());
		} else {
			char fallback[64];
			std::snprintf(fallback, sizeof(fallback),
				      "<image:%" PRIu64 ">", image_id);
			w.String(fallback);
		}

		w.Key("memops");
		w.StartArray();

		for (const auto &[pc, pc_log] : logs) {
			w.StartObject();

			w.Key("pc");
			w.Uint64(pc);

			w.Key("before");
			write_access_map(w, pc_log.before_patch);

			w.Key("after");
			write_access_map(w, pc_log.after_patch);

			w.EndObject();
		}

		w.EndArray();
		w.EndObject();
	}

	w.EndArray();

	w.EndObject();

	/*
	 * FileWriteStream buffers output internally. Flush it before checking
	 * the FILE state. The FILE itself remains owned by the caller.
	 */
	stream.Flush();

	if (std::ferror(file)) {
		std::perror("sanemaker: writing access log");
		return false;
	}

	return true;
}
