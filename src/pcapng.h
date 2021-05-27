#include <cstddef>
#include <filesystem>
#include <span>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <string_view>
#include <vector>

#include <windows.h>

template <typename T>
concept payload
	= !std::convertible_to<T, std::span<std::byte const>>
	&& !std::convertible_to<T, std::string_view>;

struct pcapng_writer
{
	pcapng_writer(std::filesystem::path const & path)
	{
		_h = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, 0, nullptr);
		if (_h == INVALID_HANDLE_VALUE)
			throw std::system_error(GetLastError(), std::system_category());

		_new_block(0x0a0d0d0a);
		_append(_section_header_t{
			.magic = 0x1a2b3c4d,
			.major_version = 1,
			.minor_version = 0,
			.section_length = -1,
			});
		_end_block();
	}

	~pcapng_writer()
	{
		if (_h != INVALID_HANDLE_VALUE)
			CloseHandle(_h);
	}

	uint32_t add_interface(uint16_t link_type, std::string name, std::string desc, size_t snaplen)
	{
		switch (link_type)
		{
		case 6:
			link_type = 1;
			break;
		case 71:
			link_type = 105;
			break;
		}

		uint32_t r = _intf_count++;
		_interface_desc_t intf = {
			.link_type = link_type,
			.snaplen = (uint32_t)snaplen,
		};

		_new_block(1);
		_append(intf);
		_opt(2, name);
		_opt(3, desc);
		_opt(0, std::span<std::byte const>{});
		_end_block();
		return r;
	}

	void add_packet(uint32_t ifidx, uint64_t timestamp, std::span<std::byte const> payload, size_t full_length)
	{
		_new_block(6);
		_append(_enhanced_packet_t{
			.intf_id = ifidx,
			.timestamp_hi = (uint32_t)(timestamp >> 32),
			.timestamp_lo = (uint32_t)timestamp,
			.captured_len = (uint32_t)payload.size(),
			.packet_len = (uint32_t)full_length,
			});
		_append(payload);
		_pad();
		_opt(0, std::span<std::byte const>{});
		_end_block();
	}

private:
	void _pad()
	{
		_buf.resize((_buf.size() + 3) & ~3);
	}

	void _new_block(uint32_t type)
	{
		_buf.clear();
		this->_append(type);
		this->_append((uint32_t)0);
	}

	void _end_block()
	{
		uint32_t len = (uint32_t)(_buf.size() + 4);
		_append(len);
		*(uint32_t *)&_buf[4] = len;

		_write(_buf);
	}

	void _append(std::span<std::byte const> data)
	{
		_buf.insert(_buf.end(), data.begin(), data.end());
	}

	template <payload T>
	void _append(T const & t)
	{
		this->_append(std::as_bytes(std::span<T const>{ &t, 1 }));
	}

	void _opt(uint16_t type, std::span<std::byte const> payload)
	{
		this->_append(type);
		this->_append((uint16_t)payload.size());
		this->_append(payload);
		_pad();
	}

	template <payload T>
	void _opt(uint16_t type, T const & payload)
	{
		this->_opt(type, std::as_bytes({ &payload, 1 }));
	}

	void _opt(uint16_t type, std::string_view payload)
	{
		this->_opt(type, std::as_bytes(std::span<char const>{ payload.data(), payload.size() }));
	}

	template <payload T>
	void _write(T const & data)
	{
		this->_write(std::as_bytes(std::span<T const>{ &data, 1 }));
	}

	void _write(std::span<std::byte const> data)
	{
		OVERLAPPED ov = {};
		ov.Offset = 0xffffffff;
		ov.OffsetHigh = 0xffffffff;
		while (!data.empty())
		{
			DWORD written;
			if (!WriteFile(_h, data.data(), (DWORD)data.size(), &written, &ov))
				throw std::system_error(GetLastError(), std::system_category());

			data = data.subspan(written);
		}
	}

	struct _section_header_t
	{
		uint32_t magic;
		uint16_t major_version;
		uint16_t minor_version;
		int64_t section_length;
	};

	struct _interface_desc_t
	{
		uint16_t link_type;
		uint16_t _0a;
		uint32_t snaplen;
	};

	struct _enhanced_packet_t
	{
		uint32_t intf_id;
		uint32_t timestamp_hi;
		uint32_t timestamp_lo;
		uint32_t captured_len;
		uint32_t packet_len;
	};


	std::vector<std::byte> _buf;

	HANDLE _h;
	uint32_t _intf_count = 0;
};

#pragma once
