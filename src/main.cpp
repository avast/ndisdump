#include "cmdline.h"
#include "comptr.h"
#include "hr.h"
#include "pcapng.h"
#include "registry.h"
#include "sigint.h"
#include "utf8.h"

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <iphlpapi.h>
#include <objbase.h>
#include <Netcfgx.h>
#include <devguid.h>

#include <cstddef>
#include <concepts>
#include <functional>
#include <filesystem>
#include <iostream>
#include <map>
#include <span>


namespace Microsoft_Windows_NDIS_PacketCapture {
	static constexpr GUID id = { 0x2ED6006E, 0x4729, 0x4609, { 0xB4, 0x23, 0x3E, 0xE7, 0xBC, 0xD6, 0x78, 0xEF } };

	enum: uint32_t
	{
		packet_fragment = 1001,
	};
}

template <typename T>
static T read_ne(std::span<std::byte const> & data)
{
	if (data.size() < sizeof(T))
		throw std::runtime_error("invalid");
	T r;
	memcpy(&r, data.data(), sizeof(T));
	data = data.subspan(sizeof(T));
	return r;
}

struct ndis_packetcapture_consumer
{
	ndis_packetcapture_consumer(std::shared_ptr<pcapng_writer> writer, size_t snaplen)
		: _writer(std::move(writer)), _snaplen(snaplen)
	{
	}

	void push_trace(PEVENT_RECORD event)
	{
		if (event->EventHeader.ProviderId != Microsoft_Windows_NDIS_PacketCapture::id)
			return;

		auto const & ed = event->EventHeader.EventDescriptor;
		std::span<std::byte const> data = { (std::byte const *)event->UserData, event->UserDataLength };

		switch ((ed.Version << 16) | ed.Id)
		{
		case Microsoft_Windows_NDIS_PacketCapture::packet_fragment:
		{
			auto miniport_intf_index = read_ne<uint32_t>(data);
			auto lower_intf_index = read_ne<uint32_t>(data);
			auto fragment_size = read_ne<uint32_t>(data);

			auto it = _intfs.find(miniport_intf_index);
			if (it == _intfs.end())
			{
				MIB_IFROW row = {};
				row.dwIndex = miniport_intf_index;
				if (GetIfEntry(&row) != 0)
					return;

				auto ifidx = _writer->add_interface((uint16_t)row.dwType, to_utf8(row.wszName),
					(char const *)row.bDescr, _snaplen);
				it = _intfs.emplace(miniport_intf_index, ifidx).first;
			}

			if (data.size() < fragment_size)
				throw std::runtime_error("invalid");

			std::span<std::byte const> fragment(data.data(), fragment_size);
			data = data.subspan(fragment_size);
			_writer->add_packet(it->second, (event->EventHeader.TimeStamp.QuadPart / 10) - 11644473600000000l,
				fragment.subspan(0, (std::min)(fragment.size(), _snaplen)), fragment.size());
			break;
		}
		}
	}

private:
	std::shared_ptr<pcapng_writer> _writer;
	std::map<uint32_t, uint32_t> _intfs;
	size_t _snaplen;
};


template <typename F>
void foreach_net_binding(LPCWSTR component_name, F && fn)
{
	comptr<INetCfg> netcfg;
	hrtry CoCreateInstance(CLSID_CNetCfg, nullptr, CLSCTX_INPROC_SERVER, IID_INetCfg, (void **)~netcfg);

	auto lock = netcfg.query<INetCfgLock>();
	hrtry lock->AcquireWriteLock(5000, L"ndisdump", nullptr);

	hrtry netcfg->Initialize(nullptr);

	comptr<INetCfgComponent> ndiscap;
	hrtry netcfg->FindComponent(component_name, ~ndiscap);

	auto bindings = ndiscap.query<INetCfgComponentBindings>();

	comptr<IEnumNetCfgBindingPath> binding_paths;
	hrtry bindings->EnumBindingPaths(EBP_ABOVE, ~binding_paths);

	for (;;)
	{
		comptr<INetCfgBindingPath> path;

		ULONG fetched;
		auto hr = hrtry binding_paths->Next(1, ~path, &fetched);
		if (hr == S_FALSE)
			break;

		fn(path);
	}

	hrtry netcfg->Apply();
	hrtry lock->ReleaseWriteLock();
}

struct _ndiscap_sentry
{
	_ndiscap_sentry()
		: _key(win32_reg_handle::open_key(HKEY_LOCAL_MACHINE, LR"(SYSTEM\CurrentControlSet\Services\NdisCap\Parameters)", KEY_QUERY_VALUE | KEY_SET_VALUE))
	{
		uint32_t refcount = _key.query_dword(L"RefCount", 0);
		_key.set_dword(L"RefCount", refcount + 1);

		foreach_net_binding(L"ms_ndiscap", [](comptr<INetCfgBindingPath> const & path) {
			hrtry path->Enable(TRUE);
			});
	}

	~_ndiscap_sentry()
	{
		uint32_t refcount = _key.query_dword(L"RefCount", 0);
		_key.set_dword(L"RefCount", refcount - 1);

		if (refcount == 1)
		{
			foreach_net_binding(L"ms_ndiscap", [](comptr<INetCfgBindingPath> const & path) {
				hrtry path->Enable(FALSE);
				});
		}
	}

private:
	win32_reg_handle _key;
};

struct service_handle
{
	explicit service_handle(SC_HANDLE h) noexcept
		: _h(h)
	{
	}

	explicit operator bool() const noexcept
	{
		return _h != nullptr;
	}

	SC_HANDLE get() const noexcept
	{
		return _h;
	}

	~service_handle()
	{
		if (_h)
			CloseServiceHandle(_h);
	}

	service_handle(service_handle && o) noexcept
		: _h(std::exchange(o._h, nullptr))
	{
	}

	service_handle & operator=(service_handle o) noexcept
	{
		std::swap(_h, o._h);
		return *this;
	}

private:
	SC_HANDLE _h;
};

static void _start_service(LPCWSTR name)
{
	service_handle scman(OpenSCManagerW(nullptr, SERVICES_ACTIVE_DATABASEW, SC_MANAGER_CONNECT));
	if (!scman)
	{
		DWORD err = GetLastError();
		throw std::system_error(err, std::system_category());
	}

	service_handle service(OpenServiceW(scman.get(), name, SERVICE_QUERY_STATUS));
	if (!service)
	{
		DWORD err = GetLastError();
		throw std::system_error(err, std::system_category());
	}

	SERVICE_STATUS st = {};
	if (!QueryServiceStatus(service.get(), &st))
	{
		DWORD err = GetLastError();
		throw std::system_error(err, std::system_category());
	}

	if (st.dwCurrentState == SERVICE_RUNNING)
		return;

	service = service_handle(OpenServiceW(scman.get(), name, SERVICE_QUERY_STATUS | SERVICE_START));
	if (!service)
	{
		DWORD err = GetLastError();
		throw std::system_error(err, std::system_category());
	}

	while (st.dwCurrentState != SERVICE_RUNNING)
	{
		if (st.dwCurrentState == SERVICE_STOPPED)
		{
			if (!StartServiceW(service.get(), 0, nullptr))
			{
				DWORD err = GetLastError();
				if (err != ERROR_SERVICE_ALREADY_RUNNING)
					throw std::system_error(err, std::system_category());
			}
		}

		Sleep(st.dwWaitHint);

		if (!QueryServiceStatus(service.get(), &st))
		{
			DWORD err = GetLastError();
			throw std::system_error(err, std::system_category());
		}
	}
}

static int _real_main(int argc, char * argv[])
{
	hrtry CoInitialize(nullptr);

	std::filesystem::path out_path;
	int snaplen = 262144;
	std::string expr;
	bool list_interfaces = false;

	command_line_reader clr(argc, argv);
	auto print_help = [&] {
		printf("Usage: %s [OPTIONS] -w FILE [EXPR ...]\n", clr.arg0().stem().string().c_str());
	};

	while (clr.next())
	{
		if (clr == "-D" || clr == "--list-interfaces")
		{
			list_interfaces = true;
		}
		else if (clr == "-w")
		{
			clr.pop_path(out_path);
		}
		else if (clr == "-s" || clr == "--snapshot-length")
		{
			snaplen = std::stoi(clr.pop_string());
			if (snaplen <= 0)
				snaplen = 262144;
		}
		else if (clr == "")
		{
			if (!expr.empty())
				expr.push_back(' ');
			expr.append(clr.pop_string());
		}
		else if (clr == "-h" || clr == "--help")
		{
			print_help();
			return 0;
		}
		else
		{
			print_help();
			return 2;
		}
	}

	if (list_interfaces)
	{
		ULONG size;
		DWORD err = GetIfTable(nullptr, &size, TRUE);
		if (err != ERROR_INSUFFICIENT_BUFFER)
			throw std::system_error(err, std::system_category());

		std::vector<std::byte> buf(size);
		err = GetIfTable((PMIB_IFTABLE)buf.data(), &size, TRUE);
		if (err != NO_ERROR)
			throw std::system_error(err, std::system_category());

		PMIB_IFTABLE iftable = (PMIB_IFTABLE)buf.data();

		for (DWORD i = 0; i != iftable->dwNumEntries; ++i)
		{
			MIB_IFROW const & row = iftable->table[i];
			if (row.dwType == IF_TYPE_ETHERNET_CSMACD)
				printf("[%u] %s\n", row.dwIndex, row.bDescr);
		}

		return 0;
	}

	if (out_path.empty())
	{
		print_help();
		return 2;
	}

	_start_service(L"ndiscap");
	_ndiscap_sentry ndiscap;

	alignas(EVENT_TRACE_PROPERTIES) std::byte buf[sizeof(EVENT_TRACE_PROPERTIES) + 2048] = {};
	EVENT_TRACE_PROPERTIES * etp = (EVENT_TRACE_PROPERTIES *)buf;

	ULONG err;
	TRACEHANDLE etw_session;
	for (;;)
	{
		etp->Wnode.BufferSize = sizeof buf;
		etp->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
		etp->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
		etp->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
		etp->LoggerNameOffset = etp->LogFileNameOffset + 1024;

		err = StartTraceW(&etw_session, L"wncap", etp);
		if (err == ERROR_ALREADY_EXISTS)
		{
			ControlTraceW(0, L"wncap", etp, EVENT_TRACE_CONTROL_STOP);
			continue;
		}

		if (err == ERROR_SUCCESS)
			break;

		return err;
	}

	err = EnableTraceEx(&Microsoft_Windows_NDIS_PacketCapture::id, nullptr, etw_session, TRUE, 0xff, 0xffff'ffff'ffff'ffff, 0, 0, nullptr);

	std::shared_ptr<pcapng_writer> w;
	w = std::make_shared<pcapng_writer>(out_path);

	ndis_packetcapture_consumer consumer(w, snaplen);

	struct consume_ctx_t
	{
		TRACEHANDLE h;
		ndis_packetcapture_consumer * consumer;
	};

	consume_ctx_t consume_ctx = {
		.consumer = &consumer,
	};

	EVENT_TRACE_LOGFILEW logfile = {};
	logfile.LoggerName = (LPWSTR)L"wncap";
	logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
	logfile.Context = &consume_ctx;
	logfile.EventRecordCallback = [](PEVENT_RECORD EventRecord) {
		auto * ctx = (consume_ctx_t *)EventRecord->UserContext;
		try
		{
			ctx->consumer->push_trace(EventRecord);
		}
		catch (std::exception const & e)
		{
			CloseTrace(ctx->h);
			fprintf(stderr, "error: %s\n", e.what());
		}
	};

	{
		consume_ctx.h = OpenTraceW(&logfile);
		sigint_handler sigint([&] {
			CloseTrace(consume_ctx.h);
		});

		ProcessTrace(&consume_ctx.h, 1, nullptr, nullptr);
	}

	ControlTraceW(etw_session, nullptr, etp, EVENT_TRACE_CONTROL_STOP);
	return 0;
}

int main(int argc, char * argv[])
{
	try
	{
		return _real_main(argc, argv);
	}
	catch (std::exception const & e)
	{
		fprintf(stderr, "error: %s\n", e.what());
		return 1;
	}
	catch (...)
	{
		fprintf(stderr, "error: unknown error\n");
		return 1;
	}
}
