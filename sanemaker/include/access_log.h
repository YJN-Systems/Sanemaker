#pragma once

#include <cstdint>
#include <cstdio>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>

#include <target_range.h>

struct AccessKey {
	uint64_t target;
	uint64_t field;

	bool operator<(const AccessKey &other) const
	{
		if (target != other.target)
			return target < other.target;
		return field < other.field;
	}
};

struct AccessRange {
	uint64_t begin; // inclusive, field-relative
	uint64_t end; // exclusive, field-relative
};

using AccessMap = std::map<AccessKey, std::vector<AccessRange> >;

struct PcAccessLog {
	AccessMap before_patch;
	AccessMap after_patch;
};

class AccessLogger {
    public:
	void register_image(uint64_t image_id, const std::string &name);

	void log(uint64_t image_id, uint64_t pc,
		 const std::vector<TargetRangeHit> &hits, bool after_patch);

	bool write(FILE *file) const;

    private:
	mutable std::mutex lock_;

	uint64_t target_index(const std::string &hash);

	std::unordered_map<std::string, uint64_t> target_by_hash_;
	std::map<uint64_t, std::string> image_names_;
	std::map<uint64_t, std::map<uint64_t, PcAccessLog> > logs_by_image_;
};
