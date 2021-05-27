#include <system_error>
#include <utility>
#include <windows.h>

struct win32_reg_handle
{
	static win32_reg_handle open_key(HKEY root, LPCWSTR key_name, DWORD desired_access)
	{
		HKEY key;
		DWORD err = RegOpenKeyExW(root, key_name, 0, desired_access, &key);
		if (err != ERROR_SUCCESS)
			throw std::system_error(err, std::system_category());
		return win32_reg_handle(key);
	}

	win32_reg_handle() noexcept
		: _h(nullptr)
	{
	}

	explicit win32_reg_handle(HKEY h) noexcept
		: _h(h)
	{
	}

	HKEY get() const noexcept
	{
		return _h;
	}

	uint32_t query_dword(LPCWSTR value_name, uint32_t def) const
	{
		DWORD type;
		uint32_t r;
		DWORD size = sizeof r;
		DWORD err = RegQueryValueExW(_h, value_name, nullptr, &type, (LPBYTE)&r, &size);

		if (err == ERROR_FILE_NOT_FOUND)
			return def;

		if (err != ERROR_SUCCESS)
			throw std::system_error(err, std::system_category());

		if (type != REG_DWORD)
			throw std::system_error(ERROR_INVALID_PARAMETER, std::system_category());

		return r;
	}

	void set_dword(LPCWSTR value_name, uint32_t value)
	{
		auto err = RegSetValueExW(_h, value_name, 0, REG_DWORD, (BYTE const *)&value, sizeof value);
		if (err != ERROR_SUCCESS)
			throw std::system_error(err, std::system_category());
	}

	~win32_reg_handle()
	{
		if (_h)
			RegCloseKey(_h);
	}

	win32_reg_handle(win32_reg_handle && o) noexcept
		: _h(std::exchange(o._h, nullptr))
	{
	}

	win32_reg_handle & operator=(win32_reg_handle o) noexcept
	{
		std::swap(_h, o._h);
		return *this;
	}

private:
	HKEY _h;
};

#pragma once
