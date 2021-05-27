#include "utf8.h"

#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>

#include <windows.h>

struct command_line_reader
{
	command_line_reader()
		: command_line_reader(::GetCommandLineW())
	{
	}

	command_line_reader(int argc, char const * const argv[])
		: command_line_reader(::GetCommandLineW())
	{
	}

	explicit command_line_reader(wchar_t const * cmdline)
	{
		wchar_t ** argv = ::CommandLineToArgvW(cmdline, &_argc);
		if (!argv)
		{
			DWORD err = ::GetLastError();
			throw std::system_error(err, std::system_category());
		}

		_argv.reset(argv);

		_arg0 = this->pop_path();
	}

	std::filesystem::path const & arg0() const noexcept
	{
		return _arg0;
	}

	bool next()
	{
		if (_forced_arg)
			throw std::runtime_error("XXX unexpected argument");

	retry:
		if (*_short_opts)
		{
			_opt.resize(2);
			_opt[0] = '-';
			_opt[1] = (char)*_short_opts++;

			if (*_short_opts == '=')
			{
				_forced_arg = _short_opts + 1;
				_short_opts = L"";
			}
			return true;
		}

		if (_idx >= _argc)
			return false;

		wchar_t const * cur = _argv[_idx++];
		if (_parse_opts && cur[0] == '-' && cur[1] != 0 && cur[1] != '=')
		{
			if (cur[1] == '-')
			{
				if (cur[2] == 0)
				{
					_parse_opts = false;
					_opt.clear();
					_forced_arg = cur;
				}
				else
				{
					_apply_long_arg(cur);
				}
			}
			else
			{
				_short_opts = cur + 1;
				goto retry;
			}
		}
		else
		{
			_opt.clear();
			_forced_arg = cur;
		}

		return true;
	}

	friend bool operator==(command_line_reader const & lhs, std::string_view rhs) noexcept
	{
		return lhs._opt == rhs;
	}

	std::string pop_string()
	{
		if (_forced_arg)
			return to_utf8(std::exchange(_forced_arg, nullptr));

		if (_idx >= _argc)
			throw std::runtime_error("XXX expected an argument");

		return to_utf8(_argv[_idx++]);
	}

	void pop_path(std::filesystem::path & out)
	{
		if (!out.empty())
			throw std::runtime_error("XXX argument already specified");

		out = this->pop_path();
		if (out.empty())
			throw std::runtime_error("XXX argument must be non-empty");
	}

	std::filesystem::path pop_path()
	{
		if (_forced_arg)
			return std::exchange(_forced_arg, nullptr);

		if (_idx >= _argc)
			throw std::runtime_error("XXX expected an argument");

		return _argv[_idx++];
	}

private:
	void _apply_long_arg(wchar_t const * arg)
	{
		wchar_t const * p = arg + 2;
		for (;;)
		{
			switch (*p)
			{
			case '=':
				_forced_arg = p + 1;
				[[fallthrough]];

			case 0:
				_opt = to_utf8({ arg, size_t(p - arg) });
				return;

			default:
				++p;
			}
		}
	}

	struct _win32_local_deleter
	{
		void operator()(void const * p)
		{
			if (p)
				::LocalFree((HLOCAL)p);
		}
	};

	int _argc;
	int _idx = 0;
	std::unique_ptr<wchar_t const * const[], _win32_local_deleter> _argv;

	bool _parse_opts = true;
	wchar_t const * _short_opts = L"";
	wchar_t const * _forced_arg = nullptr;

	std::string _opt;
	std::filesystem::path _arg0;
};

#pragma once
