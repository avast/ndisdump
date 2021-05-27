#include <string>
#include <string_view>
#include <system_error>

#include <windows.h>

std::string to_utf8(std::wstring_view s)
{
	int r = WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0, nullptr, nullptr);
	if (r < 0)
		throw std::system_error(GetLastError(), std::system_category());
	std::string ss;
	ss.resize(r + 1);
	r = WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), ss.data(), (int)ss.size(), nullptr, nullptr);
	if (r < 0)
		throw std::system_error(GetLastError(), std::system_category());
	ss.resize(r);
	return ss;
}

#pragma once
