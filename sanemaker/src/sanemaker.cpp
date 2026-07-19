/*
 * Sanemaker QEMU TCG plugin.
 *
 * Guest code communicates with the plugin through trapped function calls.
 * Those traps register target objects, publish their current field layouts,
 * and register dynamically loaded code ranges.
 *
 * Memory callbacks then translate:
 *
 *   runtime memory address -> tagged object -> object field(s)
 *   runtime instruction PC -> image ID and image-relative PC
 *
 * Accesses are aggregated by instruction, target type, and field, with
 * separate buckets for accesses observed before and after the Selfpatch-SLR
 * patch boundary.
 */

#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>
#include <list>
#include <mutex>
#include <thread>
#include <filesystem>
#include <unistd.h>
#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <system_error>

#include <metadata.h>
#include <code_range.h>
#include <target_range.h>
#include <access_log.h>

extern "C" {
#include QEMU_PLUGIN_HDR
}

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

namespace
{

struct InsnInfo {
	uint64_t runtime_pc;
};

struct ImageInfo {
	uint64_t id;
	std::string name;
	uint64_t runtime_base;
};

/* Numeric values are part of the guest/plugin ABI; do not renumber. */
enum class SanemakerFetch : uint64_t {
	SpslrEnabled = 1,
};

/* Numeric values are part of the guest/plugin ABI; do not renumber. */
enum class SanemakerSignal : uint64_t {
	PatchBoundary = 1,
	Pause = 2,
	Resume = 3,
};

struct ThreadInfo {
	bool paused = false;
};

struct UniqueLogFile {
	FILE *file = nullptr;
	std::filesystem::path temporary_path;
	std::filesystem::path final_path;
};

static bool create_unique_log_file(const std::filesystem::path &logdir,
				   UniqueLogFile &result)
{
	/*
	 * mkstemps() replaces exactly the six X characters while preserving
	 * the suffix. The incomplete file therefore has a name such as:
	 *
	 *     sanemaker.aB3xYz.json.tmp
	 */
	std::string pattern = (logdir / "sanemaker.XXXXXX.json.tmp").string();

	std::vector<char> path_buffer(pattern.begin(), pattern.end());
	path_buffer.push_back('\0');

	constexpr int suffix_length = sizeof(".json.tmp") - 1;

	int fd = ::mkstemps(path_buffer.data(), suffix_length);
	if (fd < 0) {
		std::fprintf(stderr, "sanemaker: mkstemps(%s) failed: %s\n",
			     pattern.c_str(), std::strerror(errno));
		return false;
	}

	FILE *file = ::fdopen(fd, "w");
	if (!file) {
		int saved_errno = errno;

		::close(fd);
		::unlink(path_buffer.data());

		std::fprintf(stderr, "sanemaker: fdopen(%s) failed: %s\n",
			     path_buffer.data(), std::strerror(saved_errno));
		return false;
	}

	result.file = file;
	result.temporary_path = path_buffer.data();

	std::string final_name = result.temporary_path.string();
	constexpr const char temporary_suffix[] = ".tmp";

	if (final_name.size() < sizeof(temporary_suffix) - 1) {
		std::fprintf(
			stderr,
			"sanemaker: generated temporary path is invalid: %s\n",
			final_name.c_str());

		std::fclose(file);
		result.file = nullptr;
		::unlink(result.temporary_path.c_str());
		return false;
	}

	final_name.erase(final_name.size() - (sizeof(temporary_suffix) - 1));

	result.final_path = std::move(final_name);
	return true;
}

static bool write_log_atomically(const AccessLogger &logger,
				 const std::filesystem::path &logdir)
{
	UniqueLogFile output;

	if (!create_unique_log_file(logdir, output))
		return false;

	bool write_ok = logger.write(output.file);

	/*
	 * Flush the C stdio layer. AccessLogger flushes RapidJSON's own
	 * FileWriteStream, but fflush() is still needed to push stdio-buffered
	 * bytes to the file descriptor.
	 */
	if (write_ok && std::fflush(output.file) != 0) {
		std::fprintf(stderr, "sanemaker: fflush(%s) failed: %s\n",
			     output.temporary_path.c_str(),
			     std::strerror(errno));
		write_ok = false;
	}

	/*
	 * Ensure the completed JSON reaches the backing filesystem before it
	 * is published under its final name.
	 *
	 * This is stronger than strictly necessary for uniqueness, but useful
	 * when the final .json file should not appear until its contents have
	 * been successfully written.
	 */
	if (write_ok) {
		int fd = ::fileno(output.file);

		if (fd < 0) {
			std::fprintf(stderr,
				     "sanemaker: fileno(%s) failed: %s\n",
				     output.temporary_path.c_str(),
				     std::strerror(errno));
			write_ok = false;
		} else if (::fsync(fd) != 0) {
			std::fprintf(stderr,
				     "sanemaker: fsync(%s) failed: %s\n",
				     output.temporary_path.c_str(),
				     std::strerror(errno));
			write_ok = false;
		}
	}

	/*
	 * fclose() can report delayed write errors, so it is part of deciding
	 * whether the dump is complete.
	 */
	if (std::fclose(output.file) != 0) {
		std::fprintf(stderr, "sanemaker: fclose(%s) failed: %s\n",
			     output.temporary_path.c_str(),
			     std::strerror(errno));
		write_ok = false;
	}

	output.file = nullptr;

	if (!write_ok) {
		std::fprintf(stderr,
			     "sanemaker: incomplete log retained at %s\n",
			     output.temporary_path.c_str());
		return false;
	}

	/*
	 * mkstemps() guarantees that temporary_path was created uniquely.
	 * Renaming within the same directory/filesystem atomically publishes
	 * the completed file.
	 */
	if (::rename(output.temporary_path.c_str(),
		     output.final_path.c_str()) != 0) {
		std::fprintf(stderr, "sanemaker: rename(%s, %s) failed: %s\n",
			     output.temporary_path.c_str(),
			     output.final_path.c_str(), std::strerror(errno));
		std::fprintf(stderr,
			     "sanemaker: completed log retained at %s\n",
			     output.temporary_path.c_str());
		return false;
	}

	return true;
}

struct PluginState {
	/* Aggregated output and currently tagged guest objects/code ranges. */
	AccessLogger logger;
	TargetRangeSet tracked_memory;
	CodeRangeSet tracked_code;
	Metadata metadata;

	/*
	 * Per-instruction callback userdata allocated during TB translation.
	 * QEMU may retain these pointers until the TB cache is flushed.
	 */
	std::mutex insn_infos_lock;
	std::vector<InsnInfo *> insn_infos;

	/* QEMU register handles are discovered separately for every vCPU. */
	std::mutex regs_lock;
	std::vector<
		std::unordered_map<std::string, struct qemu_plugin_register *> >
		regs_by_vcpu;

	std::string logdir;

	/*
	 * Dynamic image registry. Image IDs remain stable when an image with the
	 * same name is registered again, while its old code ranges are discarded.
	 */
	std::mutex images_lock;
	uint64_t next_image_id = 1;
	std::unordered_map<std::string, uint64_t> image_id_by_name;
	std::unordered_map<uint64_t, ImageInfo> image_by_id;

	/*
	 * main_slide maps metadata/image addresses to runtime addresses:
	 * runtime_pc = image_pc + main_slide.
	 */
	uint64_t main_image_id = 0;
	uint64_t main_slide = 0;
	bool main_slide_ready = false;

	bool spslr_enabled = false;

	/*
	 * PatchBoundary is one-way: all subsequent accesses go to the "after"
	 * bucket. There is intentionally no transition back to "before".
	 */
	std::atomic<bool> host_patched{ false };

	std::mutex threads_lock;
	std::unordered_map<std::size_t, ThreadInfo> threads;

	bool entry_enabled = false;
	uint64_t entry_image_pc = 0;
	std::atomic<bool> entry_reached{ false };

	bool kill_at_enabled = false;
	uint64_t kill_at_image_pc = 0;
	std::atomic<bool> kill_at_reached{ false };

	bool system_mode = false;

	~PluginState()
	{
		if (!write_log_atomically(logger, logdir)) {
			std::fprintf(
				stderr,
				"sanemaker: failed to publish access log in %s\n",
				logdir.c_str());
		}

		clear_insn_infos();
	}

	InsnInfo *make_insn_info(uint64_t pc)
	{
		auto *info = new InsnInfo{ pc };
		std::lock_guard<std::mutex> guard(insn_infos_lock);
		insn_infos.push_back(info);
		return info;
	}

	void clear_insn_infos()
	{
		std::lock_guard<std::mutex> guard(insn_infos_lock);
		for (InsnInfo *info : insn_infos) {
			delete info;
		}
		insn_infos.clear();
	}
};

/* Do not use unique_ptr, static destructors are called before exit_cb. */
static PluginState *state = nullptr;

/*
 * In user-mode emulation, guest and host code shares the same threads. The
 * current thread can thus be used for per-guest-thread bookkeeping.
 *
 * This is not a valid guest-task identity in system emulation: multiple guest
 * tasks may execute on the same host thread. Pause/resume is therefore disabled
 * in system mode. Supporting it would require deriving a guest task identity,
 * for example from architecture/OS-specific per-task state.
 */
static std::size_t get_tid()
{
	/* Pausing in system mode is currently unsupported */
	if (state->system_mode)
		return 0;

	return std::hash<std::thread::id>()(std::this_thread::get_id());
}

static uint64_t read_guest_reg64(unsigned int vcpu_index, const char *wanted)
{
	struct qemu_plugin_register *handle = nullptr;

	{
		std::lock_guard<std::mutex> guard(state->regs_lock);

		if (vcpu_index >= state->regs_by_vcpu.size()) {
			std::fprintf(stderr,
				     "sanemaker: no register map for vcpu %u\n",
				     vcpu_index);
			return 0;
		}

		auto &map = state->regs_by_vcpu[vcpu_index];
		auto it = map.find(wanted);

		if (it == map.end()) {
			std::fprintf(
				stderr,
				"sanemaker: no QEMU register handle for %s\n",
				wanted);
			return 0;
		}

		handle = it->second;
	}

	GByteArray *buf = g_byte_array_new();
	bool ok = qemu_plugin_read_register(handle, buf);

	uint64_t value = 0;
	if (ok && buf->len >= sizeof(value))
		std::memcpy(&value, buf->data, sizeof(value));
	else
		std::fprintf(stderr, "sanemaker: failed to read register %s\n",
			     wanted);

	g_byte_array_free(buf, TRUE);
	return value;
}

static bool write_guest_reg64(unsigned int vcpu_index, const char *wanted,
			      uint64_t value)
{
	struct qemu_plugin_register *handle = nullptr;

	{
		std::lock_guard<std::mutex> guard(state->regs_lock);

		if (vcpu_index >= state->regs_by_vcpu.size()) {
			std::fprintf(stderr,
				     "sanemaker: no register map for vcpu %u\n",
				     vcpu_index);
			return false;
		}

		auto &map = state->regs_by_vcpu[vcpu_index];
		auto it = map.find(wanted);

		if (it == map.end()) {
			std::fprintf(
				stderr,
				"sanemaker: no QEMU register handle for %s\n",
				wanted);
			return false;
		}

		handle = it->second;
	}

	GByteArray *buf = g_byte_array_sized_new(sizeof(value));
	g_byte_array_set_size(buf, sizeof(value));
	std::memcpy(buf->data, &value, sizeof(value));

	bool ok = qemu_plugin_write_register(handle, buf);

	if (!ok) {
		std::fprintf(stderr, "sanemaker: failed to write register %s\n",
			     wanted);
	}

	g_byte_array_free(buf, TRUE);
	return ok;
}

static bool read_guest_bytes(uint64_t addr, void *dst, size_t len)
{
	GByteArray *buf = g_byte_array_sized_new(len);

	bool ok = qemu_plugin_read_memory_vaddr(addr, buf, len);

	if (ok && buf->len == len)
		std::memcpy(dst, buf->data, len);
	else
		ok = false;

	g_byte_array_free(buf, TRUE);
	return ok;
}

static std::string read_target_hash(uint64_t hash_ptr)
{
	unsigned char hash[16];

	if (!read_guest_bytes(hash_ptr, hash, sizeof(hash)))
		return {};

	static const char hex[] = "0123456789abcdef";
	std::string out;
	out.resize(32);

	for (size_t i = 0; i < sizeof(hash); i++) {
		out[i * 2] = hex[hash[i] >> 4];
		out[i * 2 + 1] = hex[hash[i] & 0xf];
	}

	return out;
}

static bool read_guest_string(uint64_t str_ptr, std::string &str)
{
	constexpr size_t PAGE_SIZE = 4096;
	constexpr size_t CHUNK_SIZE = 256;
	constexpr size_t MAX_STRING_SIZE = 4096;

	str.clear();

	if (!str_ptr)
		return false;

	uint64_t addr = str_ptr;
	size_t total = 0;

	while (total < MAX_STRING_SIZE) {
		size_t page_left = PAGE_SIZE - (addr & (PAGE_SIZE - 1));
		size_t want = std::min({
			CHUNK_SIZE,
			page_left,
			MAX_STRING_SIZE - total,
		});

		uint8_t buf[CHUNK_SIZE];

		if (!read_guest_bytes(addr, buf, want))
			return false;

		for (size_t i = 0; i < want; i++) {
			if (buf[i] == '\0')
				return true;

			str.push_back(static_cast<char>(buf[i]));
		}

		addr += want;
		total += want;
	}

	std::fprintf(stderr,
		     "sanemaker: guest string at 0x%016" PRIx64
		     " exceeds maximum size %zu\n",
		     str_ptr, MAX_STRING_SIZE);
	str.clear();
	return false;
}

/*
 * Guest representation of one finalized-layout entry:
 *
 *   uint64_t offset;  // offset of this field in final-layout order
 *   uint64_t oidx;    // original index of this final-layout entry
 *   uint64_t fidx;    // final index of the field that was originally here
 *
 * The array contains one entry per metadata field.
 */
struct FinishedLayoutField {
	uint64_t offset = 0;
	uint64_t oidx = 0;
	uint64_t fidx = 0;
};

static bool read_target_layout(uint64_t field_ptr, uint64_t field_cnt,
			       std::vector<FinishedLayoutField> &res)
{
	constexpr std::size_t FINISHED_FIELD_SIZE = sizeof(uint64_t) * 3;

	res.clear();

	std::vector<uint8_t> buf;
	buf.resize(FINISHED_FIELD_SIZE * field_cnt);

	if (!read_guest_bytes(field_ptr, buf.data(), buf.size()))
		return false;

	res.resize(field_cnt);

	for (std::size_t i = 0; i < res.size(); i++) {
		const uint8_t *field_base =
			buf.data() + (FINISHED_FIELD_SIZE * i);

		std::memcpy(&res[i].offset, field_base, sizeof(uint64_t));
		std::memcpy(&res[i].oidx, field_base + sizeof(uint64_t),
			    sizeof(uint64_t));
		std::memcpy(&res[i].fidx, field_base + sizeof(uint64_t) * 2,
			    sizeof(uint64_t));
	}

	return true;
}

void vcpu_init_cb(qemu_plugin_id_t id, unsigned int vcpu_index)
{
	(void)id;

	if (!state)
		return;

	GArray *regs = qemu_plugin_get_registers();
	if (!regs) {
		std::fprintf(stderr,
			     "sanemaker: qemu_plugin_get_registers failed\n");
		return;
	}

	std::unordered_map<std::string, struct qemu_plugin_register *> map;

	for (guint i = 0; i < regs->len; ++i) {
		qemu_plugin_reg_descriptor *desc =
			&g_array_index(regs, qemu_plugin_reg_descriptor, i);

		if (!desc->name)
			continue;

		map[desc->name] = desc->handle;
	}

	{
		std::lock_guard<std::mutex> guard(state->regs_lock);

		if (state->regs_by_vcpu.size() <= vcpu_index)
			state->regs_by_vcpu.resize(vcpu_index + 1);

		state->regs_by_vcpu[vcpu_index] = std::move(map);
	}

	g_array_free(regs, TRUE);
}

static bool handle_finish_layout(const std::shared_ptr<TargetInfo> &target,
				 const std::vector<FinishedLayoutField> &fields)
{
	/* Final field offsets, in original layout order */
	std::vector<uint64_t> final_offsets;
	final_offsets.resize(fields.size());

	/*
	 * Convert offsets stored in final-layout order back into original field order.
	 *
	 * For original field i, fields[i].fidx identifies its position in the final
	 * layout; that entry's offset is therefore the runtime offset for field i.
	 */
	for (std::size_t i = 0; i < fields.size(); i++)
		final_offsets[i] = fields[fields[i].fidx].offset;

	return target->set_current_layout(final_offsets);
}

static bool handle_fetch(unsigned int vcpu_index, SanemakerFetch what)
{
	if (!state) {
		std::fprintf(
			stderr,
			"sanemaker: handle_fetch called without plugin state\n");
		return false;
	}

	switch (what) {
	case SanemakerFetch::SpslrEnabled:
		return write_guest_reg64(
			vcpu_index,
			"rsi", // Overwrite default value (second trap arg)
			state->spslr_enabled ? 1 : 0);
	}

	std::fprintf(stderr, "sanemaker: unknown fetch selector %" PRIu64 "\n",
		     static_cast<uint64_t>(what));
	return false;
}

/*
 * Pause suppresses memory-access logging for the current guest execution
 * thread. Trap handling, image registration, and other plugin state updates
 * continue normally. Pausing is not currently supported in system mode.
 */
static void set_thread_paused(bool paused)
{
	if (state->system_mode)
		return;

	std::lock_guard<std::mutex> guard(state->threads_lock);
	state->threads[get_tid()].paused = paused;
}

static bool is_thread_paused()
{
	/* Pausing in system mode is currently unsupported */
	if (state->system_mode)
		return false;

	std::lock_guard<std::mutex> guard(state->threads_lock);

	auto it = state->threads.find(get_tid());
	if (it == state->threads.end())
		return false;

	return it->second.paused;
}

static bool handle_pause_signal()
{
	set_thread_paused(true);
	return true;
}

static bool handle_resume_signal()
{
	set_thread_paused(false);
	return true;
}

static bool handle_signal(SanemakerSignal signal)
{
	if (!state) {
		std::fprintf(
			stderr,
			"sanemaker: handle_signal called without plugin state\n");
		return false;
	}

	switch (signal) {
	case SanemakerSignal::PatchBoundary: {
		state->host_patched.store(true, std::memory_order_relaxed);
		return true;
	}
	case SanemakerSignal::Pause:
		return handle_pause_signal();
	case SanemakerSignal::Resume:
		return handle_resume_signal();
	}

	std::fprintf(stderr, "sanemaker: unknown fetch selector %" PRIu64 "\n",
		     static_cast<uint64_t>(signal));
	return false;
}

static bool handle_new_image(const std::string &image, uint64_t base)
{
	if (!state || image.empty())
		return false;

	std::lock_guard<std::mutex> guard(state->images_lock);

	auto it = state->image_id_by_name.find(image);
	uint64_t id;

	if (it == state->image_id_by_name.end()) {
		id = state->next_image_id++;
		state->image_id_by_name[image] = id;
	} else {
		id = it->second;
		state->tracked_code.remove_image(id);
	}

	state->image_by_id[id] = ImageInfo{
		id,
		image,
		base,
	};

	state->logger.register_image(id, image);

	return true;
}

static bool handle_new_image_text(const std::string &image, uint64_t begin,
				  uint64_t end)
{
	if (!state || image.empty() || begin >= end)
		return false;

	std::lock_guard<std::mutex> guard(state->images_lock);

	auto it = state->image_id_by_name.find(image);
	if (it == state->image_id_by_name.end())
		return false;

	uint64_t id = it->second;
	const ImageInfo &info = state->image_by_id[id];

	state->tracked_code.add(begin, end, id, info.runtime_base);
	return true;
}

static bool handle_drop_image(const std::string &image)
{
	if (!state || image.empty())
		return false;

	std::lock_guard<std::mutex> guard(state->images_lock);

	auto it = state->image_id_by_name.find(image);
	if (it == state->image_id_by_name.end())
		return true;

	uint64_t id = it->second;

	state->tracked_code.remove_image(id);
	state->image_by_id.erase(id);
	state->image_id_by_name.erase(it);

	return true;
}

static bool handle_drop_image_text(const std::string &image, uint64_t begin,
				   uint64_t end)
{
	if (!state || image.empty() || begin >= end)
		return false;

	std::lock_guard<std::mutex> guard(state->images_lock);

	auto it = state->image_id_by_name.find(image);
	if (it == state->image_id_by_name.end())
		return false;

	uint64_t id = it->second;
	return state->tracked_code.remove(begin, end, id);
}

/*
 * Trap ABI, currently x86-64-specific:
 *
 *   rdi, rsi, rdx  - first three trap arguments
 *   rsi            - result slot for Fetch traps
 *
 * Trap addresses and kinds are supplied by the metadata file. The instruction
 * itself is only an interception point; its normal guest-side implementation
 * is expected to ensure compatibility with this ABI.
 */

/*
 * Trap argument protocol:
 *
 *   Tag:           rdi = object base, rsi = pointer to 16-byte target hash
 *   Untag:         rdi = object base
 *   FinishLayout:  rdi = layout array, rsi = pointer to target hash
 *   Fetch:         rdi = SanemakerFetch selector; result returned in rsi
 *   Signal:        rdi = SanemakerSignal selector
 *   NewImage:      rdi = image-name string, rsi = runtime image base
 *   NewImageText:  rdi = image-name string, rsi = begin, rdx = end
 *   DropImage:     rdi = image-name string
 *   DropImageText: rdi = image-name string, rsi = begin, rdx = end
 */

void trap_exec_cb(unsigned int vcpu_index, void *userdata)
{
	if (!state)
		return;

	auto *trap = static_cast<const TrapInfo *>(userdata);

	uint64_t rdi = read_guest_reg64(vcpu_index, "rdi");
	uint64_t rsi = read_guest_reg64(vcpu_index, "rsi");
	uint64_t rdx = read_guest_reg64(vcpu_index, "rdx");

	switch (trap->kind) {
	case TrapKind::Tag: {
		uint64_t object = rdi;
		uint64_t hash_ptr = rsi;

		if (!object || !hash_ptr)
			return;

		std::string hash = read_target_hash(hash_ptr);
		if (hash.empty()) {
			std::fprintf(
				stderr,
				"sanemaker: failed to read target hash at 0x%016" PRIx64
				"\n",
				hash_ptr);
			return;
		}

		auto target = state->metadata.target_by_hash(hash);
		if (!target) {
			std::fprintf(
				stderr,
				"sanemaker: tag trap references unknown target hash %s\n",
				hash.c_str());
			return;
		}

		if (!state->tracked_memory.add(object, target)) {
			std::fprintf(stderr,
				     "sanemaker: failed to track object "
				     "base=0x%016" PRIx64 " size=0x%016" PRIx64
				     " target=%s\n",
				     object, target->size,
				     target->hash.c_str());
		}

		break;
	}

	case TrapKind::Untag: {
		uint64_t object = rdi;

		if (!object)
			return;

		if (!state->tracked_memory.remove_exact(object)) {
			std::fprintf(stderr,
				     "sanemaker: untag trap for unknown object "
				     "base=0x%016" PRIx64 "\n",
				     object);
		}

		break;
	}

	case TrapKind::FinishLayout: {
		uint64_t field_ptr = rdi;
		uint64_t hash_ptr = rsi;

		if (!field_ptr || !hash_ptr)
			return;

		std::string hash = read_target_hash(hash_ptr);
		if (hash.empty()) {
			std::fprintf(
				stderr,
				"sanemaker: failed to read target hash at 0x%016" PRIx64
				"\n",
				hash_ptr);
			return;
		}

		auto target = state->metadata.target_by_hash(hash);
		if (!target) {
			std::fprintf(
				stderr,
				"sanemaker: finish_layout trap references unknown target hash %s\n",
				hash.c_str());
			return;
		}

		std::vector<FinishedLayoutField> finished_fields;

		if (!read_target_layout(field_ptr, target->fields.size(),
					finished_fields)) {
			std::fprintf(
				stderr,
				"sanemaker: failed to read finished layout at 0x%016" PRIx64
				"\n",
				field_ptr);
			return;
		}

		if (!handle_finish_layout(target, finished_fields)) {
			std::fprintf(
				stderr,
				"sanemaker: failed to update finished layout for target %s\n",
				hash.c_str());
			return;
		}

		break;
	}

	case TrapKind::Fetch: {
		SanemakerFetch what = static_cast<SanemakerFetch>(rdi);

		if (!handle_fetch(vcpu_index, what)) {
			std::fprintf(stderr,
				     "sanemaker: failed to handle fetch\n");
			return;
		}

		break;
	}

	case TrapKind::Signal: {
		SanemakerSignal signal = static_cast<SanemakerSignal>(rdi);

		if (!handle_signal(signal)) {
			std::fprintf(stderr,
				     "sanemaker: failed to handle signal\n");
			return;
		}

		break;
	}

	case TrapKind::NewImage: {
		uint64_t name_ptr = rdi;
		uint64_t base_ptr = rsi;

		std::string name;
		if (!read_guest_string(name_ptr, name)) {
			std::fprintf(
				stderr,
				"sanemaker: failed to get new image name\n");
			return;
		}

		if (!handle_new_image(name, base_ptr)) {
			std::fprintf(
				stderr,
				"sanemaker: failed to handle new image \"%s\"\n",
				name.c_str());
			return;
		}

		break;
	}

	case TrapKind::NewImageText: {
		uint64_t image_name_ptr = rdi;
		uint64_t begin_ptr = rsi;
		uint64_t end_ptr = rdx;

		std::string image;
		if (!read_guest_string(image_name_ptr, image)) {
			std::fprintf(
				stderr,
				"sanemaker: failed to get image name for new text segment\n");
			return;
		}

		if (!handle_new_image_text(image, begin_ptr, end_ptr)) {
			std::fprintf(
				stderr,
				"sanemaker: failed to handle new text segment for image \"%s\"\n",
				image.c_str());
			return;
		}

		break;
	}

	case TrapKind::DropImage: {
		uint64_t image_name_ptr = rdi;

		std::string image;
		if (!read_guest_string(image_name_ptr, image)) {
			std::fprintf(
				stderr,
				"sanemaker: failed to get name of image to drop\n");
			return;
		}

		if (!handle_drop_image(image)) {
			std::fprintf(stderr,
				     "sanemaker: failed to drop image \"%s\"\n",
				     image.c_str());
			return;
		}

		break;
	}

	case TrapKind::DropImageText: {
		uint64_t image_name_ptr = rdi;
		uint64_t begin_ptr = rsi;
		uint64_t end_ptr = rdx;

		std::string image;
		if (!read_guest_string(image_name_ptr, image)) {
			std::fprintf(
				stderr,
				"sanemaker: failed to get image name to drop text segment\n");
			return;
		}

		if (!handle_drop_image_text(image, begin_ptr, end_ptr)) {
			std::fprintf(
				stderr,
				"sanemaker: failed to drop text segment for image \"%s\"\n",
				image.c_str());
			return;
		}

		break;
	}
	}
}

void kill_at_exec_cb(unsigned int vcpu_index, void *userdata)
{
	(void)vcpu_index;
	(void)userdata;

	if (!state)
		return;

	/*
	 * Losing vCPUs return immediately. They may execute and log additional memory
	 * accesses before the winning vCPU finishes serializing the log and calls
	 * _exit(), so kill-at is not a perfectly sharp multi-vCPU logging boundary.
	 */
	bool expected = false;
	if (!state->kill_at_reached.compare_exchange_strong(
		    expected, true, std::memory_order_acq_rel,
		    std::memory_order_relaxed)) {
		return;
	}

	std::fprintf(
		stderr,
		"sanemaker: killing process because kill-at location has been reached...\n");

	bool write_ok = write_log_atomically(state->logger, state->logdir);
	if (!write_ok) {
		std::fprintf(
			stderr,
			"sanemaker: failed to publish access log in %s at kill-at\n",
			state->logdir.c_str());
	}

	/*
	 * There is no public plugin API for requesting that QEMU exit.
	 *
	 * _exit() also avoids running the normal plugin exit callback, which
	 * would otherwise write another log from PluginState's destructor.
	 */
	::_exit(write_ok ? EXIT_SUCCESS : EXIT_FAILURE);
}

void mem_cb(unsigned int vcpu_index, qemu_plugin_meminfo_t info, uint64_t vaddr,
	    void *userdata)
{
	(void)vcpu_index;
	(void)info;

	if (!state)
		return;

	if (is_thread_paused())
		return;

	uint64_t access_size = 1ULL << qemu_plugin_mem_size_shift(info);
	bool access_write = qemu_plugin_mem_is_store(info);

	(void)access_write; // Could later be used to expand validation

	/* Accesses to non-target memory are irrelevant */
	auto hits = state->tracked_memory.lookup(vaddr, access_size);
	if (hits.empty())
		return;

	/* Log which fields the instruction accessed  */
	auto *insn_info = static_cast<InsnInfo *>(userdata);

	auto code_loc = state->tracked_code.lookup(insn_info->runtime_pc);
	if (!code_loc) {
		std::fprintf(
			stderr,
			"sanemaker: target access from untracked code pc=0x%016" PRIx64
			"\n",
			insn_info->runtime_pc);
		return;
	}

	state->logger.log(code_loc->image_id, code_loc->image_pc, hits,
			  state->host_patched.load(std::memory_order_relaxed));
}

/*
 * Metadata PCs are link-time addresses. In user-mode emulation,
 * qemu_plugin_start_code() gives the runtime location corresponding to
 * metadata.code_start(), allowing a single load slide to map all main-image
 * ranges and traps.
 *
 * System mode currently assumes metadata addresses already equal runtime
 * virtual addresses and therefore uses a zero slide.
 */
void init_main_image()
{
	if (!state || state->main_slide_ready)
		return;

	if (!state->system_mode) {
		uint64_t runtime_code_start = qemu_plugin_start_code();
		uint64_t image_code_start = state->metadata.code_start();

		if (runtime_code_start == 0) {
			std::fprintf(
				stderr,
				"sanemaker: qemu_plugin_start_code returned 0\n");
			return;
		}

		state->main_slide = runtime_code_start - image_code_start;
		state->main_slide_ready = true;
	} else {
		state->main_slide = 0;
		state->main_slide_ready = true;
	}

	state->logger.register_image(state->main_image_id, "<main>");

	for (const Range &r : state->metadata.code_ranges()) {
		state->tracked_code.add(r.begin + state->main_slide,
					r.end + state->main_slide,
					state->main_image_id,
					state->main_slide);
	}
}

/* This boundary is only valid for x86_64 with 4-level paging */
static constexpr uint64_t KERNELSPACE_BEGIN = 0x0000800000000000ULL;

static bool is_userspace_address(uint64_t address)
{
	return address < KERNELSPACE_BEGIN;
}

/*
 * Instrument every eligible instruction rather than filtering by code range
 * here. Dynamic images may be registered after a TB was translated, so the
 * authoritative runtime-PC-to-image check is deferred to mem_cb().
 */
void tb_trans_cb(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
	(void)id;

	if (!state)
		return;

	init_main_image();

	const size_t n = qemu_plugin_tb_n_insns(tb);

	/*
	 * Once entry_reached becomes true, it remains true for the lifetime
	 * of the plugin. Acquire/release ordering is sufficient for publishing
	 * the transition between concurrent translation threads.
	 */
	bool attach_memory_callbacks =
		!state->entry_enabled ||
		state->entry_reached.load(std::memory_order_acquire);

	for (size_t i = 0; i < n; ++i) {
		struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);

		uint64_t runtime_pc = qemu_plugin_insn_vaddr(insn);

		/* Ignore all user-space code if in system mode */
		if (state->system_mode && is_userspace_address(runtime_pc))
			continue;

		uint64_t main_image_pc = runtime_pc - state->main_slide;

		if (state->kill_at_enabled &&
		    main_image_pc == state->kill_at_image_pc) {
			qemu_plugin_register_vcpu_insn_exec_cb(
				insn, kill_at_exec_cb, QEMU_PLUGIN_CB_NO_REGS,
				nullptr);
		}

		/* Traps can only be defined in the main image */
		const auto &traps = state->metadata.traps_by_image_pc();
		auto trap_it = traps.find(main_image_pc);
		if (trap_it != traps.end()) {
			qemu_plugin_register_vcpu_insn_exec_cb(
				insn, trap_exec_cb, QEMU_PLUGIN_CB_RW_REGS,
				const_cast<TrapInfo *>(&trap_it->second));
		}

		/*
		 * entry= is a translation-time gate, not an execution-time gate. Memory
		 * callbacks are enabled once a TB containing the configured PC is translated;
		 * the guest need not have executed that instruction yet.
		 */
		if (!attach_memory_callbacks) {
			if (main_image_pc != state->entry_image_pc)
				continue;

			state->entry_reached.store(true,
						   std::memory_order_release);
			attach_memory_callbacks = true;
		}

		InsnInfo *raw_insn_info = state->make_insn_info(runtime_pc);

		qemu_plugin_register_vcpu_mem_cb(insn, mem_cb,
						 QEMU_PLUGIN_CB_NO_REGS,
						 QEMU_PLUGIN_MEM_RW,
						 raw_insn_info);
	}
}

/* Called when tb cache is invalidated, all tb userdata can be cleared here. */
void flush_cb(qemu_plugin_id_t id)
{
	(void)id;

	if (!state)
		return;

	state->clear_insn_infos();
}

void exit_cb(qemu_plugin_id_t id, void *userdata)
{
	(void)id;
	(void)userdata;

	delete state;
	state = nullptr;
}

} // namespace

static bool parse_boolean_arg(const char *name, const char *value, bool &res)
{
	if (!value)
		return true; // Leave it as is

	if (std::strcmp(value, "on") == 0) {
		res = true;
		return true;
	} else if (std::strcmp(value, "off") == 0) {
		res = false;
		return true;
	}

	std::fprintf(
		stderr,
		"sanemaker: invalid boolean value %s=\"%s\", expected \"on\" or \"off\"\n",
		name, value);
	return false;
}

static bool parse_uint64_arg(const char *name, const char *value,
			     uint64_t &result)
{
	if (!value || value[0] == '\0') {
		std::fprintf(stderr, "sanemaker: missing value for %s\n", name);
		return false;
	}

	/*
	 * Do not accept a leading minus sign. strtoull() would otherwise
	 * convert negative input according to unsigned arithmetic.
	 */
	if (value[0] == '-') {
		std::fprintf(stderr,
			     "sanemaker: invalid value %s=\"%s\": "
			     "expected a non-negative integer\n",
			     name, value);
		return false;
	}

	errno = 0;

	char *end = nullptr;
	unsigned long long parsed = std::strtoull(value, &end, 0);

	if (errno == ERANGE) {
		std::fprintf(stderr,
			     "sanemaker: value %s=\"%s\" is out of range\n",
			     name, value);
		return false;
	}

	if (end == value || *end != '\0') {
		std::fprintf(
			stderr,
			"sanemaker: invalid value %s=\"%s\": "
			"expected a decimal or 0x-prefixed hexadecimal integer\n",
			name, value);
		return false;
	}

	result = static_cast<uint64_t>(parsed);
	return true;
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
					   const qemu_info_t *info, int argc,
					   char **argv)
{
	(void)info;

	const char *out_path = nullptr;
	const char *focus_path = nullptr;
	const char *spslr_enabled_str = nullptr;
	const char *entry_str = nullptr;
	const char *kill_at_str = nullptr;

	for (int i = 0; i < argc; ++i) {
		if (std::strncmp(argv[i], "out=", 4) == 0)
			out_path = argv[i] + 4;
		else if (std::strncmp(argv[i], "focus=", 6) == 0)
			focus_path = argv[i] + 6;
		else if (std::strncmp(argv[i], "spslr=", 6) == 0)
			spslr_enabled_str = argv[i] + 6;
		else if (std::strncmp(argv[i], "entry=", 6) == 0)
			entry_str = argv[i] + 6;
		else if (std::strncmp(argv[i], "kill-at=", 8) == 0)
			kill_at_str = argv[i] + 8;
	}

	if (!out_path || out_path[0] == '\0') {
		std::fprintf(
			stderr,
			"sanemaker: missing required argument: out=<log-directory>\n");
		return -1;
	}

	if (!std::filesystem::is_directory(out_path)) {
		std::fprintf(stderr, "sanemaker: out=%s is not a directory\n",
			     out_path);
		return -1;
	}

	if (!focus_path || focus_path[0] == '\0') {
		std::fprintf(
			stderr,
			"sanemaker: missing required argument: focus=<metadata.json>\n");
		return -1;
	}

	bool spslr_enabled = false;
	if (!parse_boolean_arg("spslr", spslr_enabled_str, spslr_enabled))
		return -1;

	bool entry_enabled = entry_str != nullptr;
	uint64_t entry_image_pc = 0;

	if (entry_enabled &&
	    !parse_uint64_arg("entry", entry_str, entry_image_pc))
		return -1;

	bool kill_at_enabled = kill_at_str != nullptr;
	uint64_t kill_at_image_pc = 0;

	if (kill_at_enabled &&
	    !parse_uint64_arg("kill-at", kill_at_str, kill_at_image_pc)) {
		return -1;
	}

	auto tmp_state = new PluginState;
	if (!tmp_state)
		return -1;

	tmp_state->logdir = out_path;
	tmp_state->spslr_enabled = spslr_enabled;
	tmp_state->entry_enabled = entry_enabled;
	tmp_state->entry_image_pc = entry_image_pc;
	tmp_state->kill_at_enabled = kill_at_enabled;
	tmp_state->kill_at_image_pc = kill_at_image_pc;
	tmp_state->system_mode = info->system_emulation;

	if (!tmp_state->metadata.load(focus_path)) {
		delete tmp_state;
		return -1;
	}

	state = tmp_state;

	qemu_plugin_register_vcpu_init_cb(id, vcpu_init_cb);
	qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans_cb);
	qemu_plugin_register_flush_cb(id, flush_cb);
	qemu_plugin_register_atexit_cb(id, exit_cb, nullptr);

	return 0;
}
