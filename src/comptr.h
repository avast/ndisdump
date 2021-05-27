#include "hr.h"
#include <concepts>
#include <unknwn.h>

template <std::derived_from<IUnknown> T>
struct comptr
{
	comptr() noexcept
		: _ptr(nullptr)
	{
	}

	explicit comptr(T * ptr) noexcept
		: _ptr(ptr)
	{
	}

	explicit operator bool() const noexcept
	{
		return _ptr != nullptr;
	}

	T * get() const noexcept
	{
		return _ptr;
	}

	T * operator->() const noexcept
	{
		return this->get();
	}

	T ** operator~() noexcept
	{
		this->reset();
		return &_ptr;
	}

	template <std::derived_from<IUnknown> Q>
	comptr<Q> query() const
	{
		if (!_ptr)
			return {};
		void * r;
		hrtry _ptr->QueryInterface(__uuidof(Q), &r);
		return comptr<Q>(static_cast<Q *>(r));
	}

	void reset(T * ptr = nullptr) noexcept
	{
		if (_ptr)
			_ptr->Release();
		_ptr = ptr;
	}

	~comptr()
	{
		this->reset();
	}

	comptr(comptr const & o) noexcept
		: _ptr(o._ptr)
	{
		if (_ptr)
			_ptr->AddRef();
	}

	comptr(comptr && o) noexcept
		: _ptr(std::exchange(o._ptr, nullptr))
	{
	}

	comptr & operator=(comptr o) noexcept
	{
		std::swap(_ptr, o._ptr);
		return *this;
	}

private:
	T * _ptr;
};

#pragma once
