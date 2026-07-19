#include <metadata.h>

#include <cerrno>
#include <cinttypes>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <mutex>
#include <algorithm>

#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/istreamwrapper.h>

namespace
{

uint64_t json_u64(const rapidjson::Value &v)
{
	if (v.IsUint64())
		return v.GetUint64();

	if (v.IsString())
		return std::strtoull(v.GetString(), nullptr, 0);

	std::fprintf(stderr, "sanemaker: expected uint64 or integer string\n");
	return 0;
}

const rapidjson::Value *member(const rapidjson::Value &obj, const char *name)
{
	auto it = obj.FindMember(name);
	if (it == obj.MemberEnd())
		return nullptr;
	return &it->value;
}

bool require_array(const rapidjson::Document &doc, const char *name,
		   const rapidjson::Value **out)
{
	auto it = doc.FindMember(name);
	if (it == doc.MemberEnd()) {
		std::fprintf(stderr, "sanemaker: missing json array '%s'\n",
			     name);
		return false;
	}

	if (!it->value.IsArray()) {
		std::fprintf(stderr,
			     "sanemaker: json field '%s' is not an array\n",
			     name);
		return false;
	}

	*out = &it->value;
	return true;
}

bool require_object_member(const rapidjson::Value &obj, const char *name,
			   const rapidjson::Value **out)
{
	if (!obj.IsObject()) {
		std::fprintf(stderr, "sanemaker: expected json object\n");
		return false;
	}

	auto it = obj.FindMember(name);
	if (it == obj.MemberEnd()) {
		std::fprintf(stderr, "sanemaker: missing json member '%s'\n",
			     name);
		return false;
	}

	*out = &it->value;
	return true;
}

bool require_string_member(const rapidjson::Value &obj, const char *name,
			   const char **out)
{
	const rapidjson::Value *v = nullptr;
	if (!require_object_member(obj, name, &v))
		return false;

	if (!v->IsString()) {
		std::fprintf(stderr,
			     "sanemaker: json member '%s' is not a string\n",
			     name);
		return false;
	}

	*out = v->GetString();
	return true;
}

bool require_u64_member(const rapidjson::Value &obj, const char *name,
			uint64_t *out)
{
	const rapidjson::Value *v = nullptr;
	if (!require_object_member(obj, name, &v))
		return false;

	*out = json_u64(*v);
	return true;
}

bool parse_trap_kind(const char *name, TrapKind *out)
{
	if (std::strcmp(name, "__sanemaker_target_tag_trap_incision") == 0) {
		*out = TrapKind::Tag;
		return true;
	}

	if (std::strcmp(name, "__sanemaker_target_untag_trap_incision") == 0) {
		*out = TrapKind::Untag;
		return true;
	}

	if (std::strcmp(name, "__sanemaker_finish_layout_trap_incision") == 0) {
		*out = TrapKind::FinishLayout;
		return true;
	}

	if (std::strcmp(name, "__sanemaker_fetch_trap_incision") == 0) {
		*out = TrapKind::Fetch;
		return true;
	}

	if (std::strcmp(name, "__sanemaker_signal_trap_incision") == 0) {
		*out = TrapKind::Signal;
		return true;
	}

	if (std::strcmp(name, "__sanemaker_new_image_trap_incision") == 0) {
		*out = TrapKind::NewImage;
		return true;
	}

	if (std::strcmp(name, "__sanemaker_new_image_text_trap_incision") ==
	    0) {
		*out = TrapKind::NewImageText;
		return true;
	}

	if (std::strcmp(name, "__sanemaker_drop_image_trap_incision") == 0) {
		*out = TrapKind::DropImage;
		return true;
	}

	if (std::strcmp(name, "__sanemaker_drop_image_text_trap_incision") ==
	    0) {
		*out = TrapKind::DropImageText;
		return true;
	}

	std::fprintf(stderr, "sanemaker: unknown trap incision symbol '%s'\n",
		     name);
	return false;
}

} // namespace

std::shared_ptr<const TargetInfo>
Metadata::target_by_hash(const std::string &hash) const
{
	auto target_it = targets_.find(hash);
	if (target_it == targets_.end())
		return {};

	return target_it->second;
}

std::shared_ptr<TargetInfo> Metadata::target_by_hash(const std::string &hash)
{
	auto target_it = targets_.find(hash);
	if (target_it == targets_.end())
		return {};

	return target_it->second;
}

bool Metadata::load(const char *path)
{
	code_start_ = 0;
	code_ranges_.clear();
	targets_.clear();
	traps_by_image_pc_.clear();

	std::ifstream in(path, std::ios::binary);
	if (!in) {
		std::fprintf(stderr,
			     "sanemaker: failed to open json '%s': %s\n", path,
			     std::strerror(errno));
		return false;
	}

	rapidjson::IStreamWrapper stream(in);

	rapidjson::Document doc;
	doc.ParseStream(stream);

	if (doc.HasParseError()) {
		std::fprintf(stderr,
			     "sanemaker: json parse error at offset %zu: %s\n",
			     doc.GetErrorOffset(),
			     rapidjson::GetParseError_En(doc.GetParseError()));
		return false;
	}

	if (!doc.IsObject()) {
		std::fprintf(stderr, "sanemaker: json root is not an object\n");
		return false;
	}

	if (!require_u64_member(doc, "code_start", &code_start_))
		return false;

	const rapidjson::Value *code = nullptr;
	if (!require_array(doc, "code", &code))
		return false;

	for (const auto &r : code->GetArray()) {
		if (!r.IsObject()) {
			std::fprintf(
				stderr,
				"sanemaker: code entry is not an object\n");
			return false;
		}

		uint64_t begin = 0;
		if (!require_u64_member(r, "start", &begin))
			return false;

		uint64_t end = 0;
		if (const rapidjson::Value *stop = member(r, "stop")) {
			end = json_u64(*stop);
		} else {
			uint64_t size = 0;
			if (!require_u64_member(r, "size", &size))
				return false;
			end = begin + size;
		}

		if (begin < end)
			code_ranges_.push_back({ begin, end });
	}

	const rapidjson::Value *targets = nullptr;
	if (!require_array(doc, "targets", &targets))
		return false;

	for (const auto &t : targets->GetArray()) {
		if (!t.IsObject()) {
			std::fprintf(
				stderr,
				"sanemaker: target entry is not an object\n");
			return false;
		}

		uint64_t id = 0;
		if (!require_u64_member(t, "id", &id))
			return false;

		const char *hash = nullptr;
		if (!require_string_member(t, "hash", &hash))
			return false;

		auto target = std::make_shared<TargetInfo>();
		target->hash = hash;

		if (!require_u64_member(t, "size", &target->size))
			return false;

		const rapidjson::Value *fields = nullptr;
		if (!require_object_member(t, "fields", &fields))
			return false;

		if (!fields->IsArray()) {
			std::fprintf(
				stderr,
				"sanemaker: target fields is not an array\n");
			return false;
		}

		for (const auto &f : fields->GetArray()) {
			if (!f.IsObject()) {
				std::fprintf(
					stderr,
					"sanemaker: field entry is not an object\n");
				return false;
			}

			FieldInfo field{};

			const char *field_name = nullptr;
			if (!require_string_member(f, "name", &field_name))
				return false;

			field.name = field_name;

			if (!require_u64_member(f, "offset", &field.offset))
				return false;

			if (!require_u64_member(f, "size", &field.size))
				return false;

			target->fields.push_back(std::move(field));
		}

		target->reset_layout();

		auto [it, inserted] = targets_.emplace(target->hash, target);
		if (!inserted) {
			std::fprintf(stderr,
				     "sanemaker: duplicate target hash '%s'\n",
				     target->hash.c_str());
			return false;
		}
	}

	const rapidjson::Value *traps = nullptr;
	if (!require_array(doc, "traps", &traps))
		return false;

	for (const auto &t : traps->GetArray()) {
		if (!t.IsObject()) {
			std::fprintf(
				stderr,
				"sanemaker: trap entry is not an object\n");
			return false;
		}

		const char *name = nullptr;
		if (!require_string_member(t, "name", &name))
			return false;

		TrapInfo trap{};
		if (!require_u64_member(t, "addr", &trap.image_pc))
			return false;

		if (!parse_trap_kind(name, &trap.kind))
			return false;

		traps_by_image_pc_[trap.image_pc] = trap;
	}

	return true;
}

void TargetInfo::rebuild_layout_indexes_unlocked()
{
	fields_by_offset_.clear();
	first_offset_by_end_.clear();

	for (uint64_t field_index = 0; field_index < fields.size();
	     ++field_index) {
		const uint64_t field_offset = current_offsets_[field_index];

		fields_by_offset_[field_offset].insert(field_index);

		const uint64_t field_size = fields[field_index].size;

		// Empty fields are represented in the layout but cannot be hit.
		if (field_size == 0)
			continue;

		/*
         * reset_layout() uses trusted metadata, while set_current_layout()
         * validates this addition before installing the layout.
         */
		const uint64_t field_end = field_offset + field_size;

		auto [it, inserted] =
			first_offset_by_end_.emplace(field_end, field_offset);

		// Multiple fields may have the same end.
		if (!inserted) {
			it->second = std::min(it->second, field_offset);
		}
	}

	/*
     * Convert:
     *
     *   end -> earliest start among fields ending exactly there
     *
     * into:
     *
     *   end -> earliest start among fields ending there or later
     */
	uint64_t earliest_offset = UINT64_MAX;

	for (auto it = first_offset_by_end_.rbegin();
	     it != first_offset_by_end_.rend(); ++it) {
		earliest_offset = std::min(earliest_offset, it->second);

		it->second = earliest_offset;
	}
}

void TargetInfo::reset_layout()
{
	std::unique_lock<std::shared_mutex> lock(layout_mutex_);

	current_offsets_.clear();
	current_offsets_.reserve(fields.size());

	for (const FieldInfo &field : fields)
		current_offsets_.push_back(field.offset);

	rebuild_layout_indexes_unlocked();
}

bool TargetInfo::set_current_layout(const std::vector<uint64_t> &offsets)
{
	if (offsets.size() != fields.size())
		return false;

	/*
     * fields and size are immutable after metadata loading, so validation
     * can happen without holding the layout lock.
     */
	for (uint64_t field_index = 0; field_index < fields.size();
	     ++field_index) {
		const uint64_t field_offset = offsets[field_index];

		const uint64_t field_size = fields[field_index].size;

		// A zero-sized field may be positioned exactly at size.
		if (field_offset > size)
			return false;

		// Overflow-safe object-bound check.
		if (field_size > size - field_offset)
			return false;
	}

	std::unique_lock<std::shared_mutex> lock(layout_mutex_);

	current_offsets_ = offsets;
	rebuild_layout_indexes_unlocked();

	return true;
}

std::vector<FieldRangeHit>
TargetInfo::fields_in_range(uint64_t access_offset, uint64_t access_size) const
{
	std::shared_lock<std::shared_mutex> lock(layout_mutex_);

	std::vector<FieldRangeHit> out;

	/*
     * Preserve the existing convention that a zero-sized lookup represents
     * a one-byte lookup.
     */
	if (access_size == 0)
		access_size = 1;

	uint64_t access_end;

	if (access_size > UINT64_MAX - access_offset)
		access_end = UINT64_MAX;
	else
		access_end = access_offset + access_size;

	if (access_end <= access_offset)
		return out;

	/*
     * The first end strictly greater than access_offset identifies the
     * earliest field start that could still overlap this access.
     */
	const auto breakpoint = first_offset_by_end_.upper_bound(access_offset);

	if (breakpoint == first_offset_by_end_.end())
		return out;

	auto field_it = fields_by_offset_.lower_bound(breakpoint->second);

	for (; field_it != fields_by_offset_.end(); ++field_it) {
		const uint64_t field_offset = field_it->first;

		// Later entries also begin outside the accessed range.
		if (field_offset >= access_end)
			break;

		for (const uint64_t field_index : field_it->second) {
			const FieldInfo &field = fields[field_index];

			if (field.size == 0)
				continue;

			const uint64_t field_end = field_offset + field.size;

			/*
             * The breakpoint only gives the earliest possible candidate.
             * Some fields encountered afterward may already have ended.
             */
			if (field_end <= access_offset)
				continue;

			const uint64_t hit_begin =
				std::max(access_offset, field_offset);

			const uint64_t hit_end =
				std::min(access_end, field_end);

			if (hit_begin >= hit_end)
				continue;

			out.push_back({
				Range{
					hit_begin - field_offset,
					hit_end - field_offset,
				},
				field_index,
			});
		}
	}

	return out;
}
