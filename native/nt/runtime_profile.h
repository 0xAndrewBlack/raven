#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <map>
#include <string>
#include <vector>

namespace raven {

// RAVEN_PROFILE=1 prints, when the process ends, how many times each native API was called and how long the host spent serving it, plus
// the time the guest ran between calls (including the cost of stopping and restarting it). It exists to find what a program waits for.
class RuntimeProfile {
public:
	static RuntimeProfile &instance()
	{
		static RuntimeProfile profile;
		return profile;
	}
	bool enabled() const { return active; }
	void api(const std::string &name, std::chrono::nanoseconds spent)
	{
		auto &entry = calls[name];
		++entry.first;
		entry.second += uint64_t(spent.count());
	}
	void guest(std::chrono::nanoseconds spent)
	{
		++resumes;
		resume_ns += uint64_t(spent.count());
	}

private:
	bool active = std::getenv("RAVEN_PROFILE") != nullptr;
	std::map<std::string, std::pair<uint64_t, uint64_t>> calls;
	uint64_t resumes = 0, resume_ns = 0;
	~RuntimeProfile()
	{
		if (!active)
			return;
		std::vector<std::pair<std::string, std::pair<uint64_t, uint64_t>>> rows(calls.begin(), calls.end());
		std::sort(rows.begin(), rows.end(), [](const auto &a, const auto &b) { return a.second.second > b.second.second; });
		uint64_t total_calls = 0, total_ns = 0;
		for (const auto &row : rows) {
			total_calls += row.second.first;
			total_ns += row.second.second;
		}
		std::cerr << "profile: " << total_calls << " API calls served in " << total_ns / 1000000 << " ms; guest ran " << resumes
			<< " times for " << resume_ns / 1000000 << " ms in total\n";
		for (size_t index = 0; index < rows.size() && index < 25; ++index)
			std::cerr << "profile: " << rows[index].first << " calls=" << rows[index].second.first << " ms=" << rows[index].second.second / 1000000
				<< " us/call=" << rows[index].second.second / 1000 / std::max<uint64_t>(rows[index].second.first, 1) << '\n';
	}
};

}
