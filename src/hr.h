#include <system_error>
#include <windows.h>

struct _hresult_checker
{
	HRESULT operator%(HRESULT hr) const
	{
		if (FAILED(hr))
			throw std::system_error(hr, std::system_category());
		return hr;
	}
};

#define hrtry ::_hresult_checker() %

#pragma once
