#include <functional>
#include <list>
#include <system_error>
#include <utility>

#include <windows.h>

struct sigint_handler
{
	sigint_handler(std::function<void()> cb)
		: _cb(std::move(cb)), _is_armed(true)
	{
		_lock_t lock;

		bool need_handlers = _cbs.empty();

		_cbs.push_back(this);
		_cb_iter = std::prev(_cbs.end());

		if (need_handlers)
		{
			if (!SetConsoleCtrlHandler(&console_ctrl_handler, TRUE))
			{
				DWORD err = GetLastError();
				throw std::system_error(err, std::system_category());
			}
		}
	}

	~sigint_handler()
	{
		_lock_t lock;
		this->_disarm_locked();
	}

	sigint_handler(sigint_handler const &) = delete;
	sigint_handler & operator=(sigint_handler const &) = delete;

private:
	static BOOL WINAPI console_ctrl_handler(DWORD dwCtrlType)
	{
		if (dwCtrlType != CTRL_C_EVENT)
			return FALSE;

		_lock_t lock;
		if (_cbs.empty())
			return FALSE;

		sigint_handler * h = _cbs.front();

		h->_disarm_locked();
		h->_cb();
		return TRUE;
	}

	void _disarm_locked()
	{
		if (_is_armed)
		{
			_cbs.erase(_cb_iter);
			_is_armed = false;
		}

		if (_cbs.empty())
			SetConsoleCtrlHandler(&console_ctrl_handler, FALSE);
	}

	std::function<void()> _cb;

	bool _is_armed;
	std::list<sigint_handler *>::iterator _cb_iter;

	struct _lock_t
	{
		_lock_t()
		{
			AcquireSRWLockExclusive(&_cbs_mutex);
		}

		~_lock_t()
		{
			ReleaseSRWLockExclusive(&_cbs_mutex);
		}
	};

	inline static SRWLOCK _cbs_mutex = {};
	inline static std::list<sigint_handler *> _cbs = {};
};

#pragma once
