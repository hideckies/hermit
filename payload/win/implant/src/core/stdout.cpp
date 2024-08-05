#include "core/stdout.hpp"

namespace Stdout
{
	std::wstring GetErrorMessage(DWORD dwErrorCode)
	{
		WCHAR* wMsgBuf = nullptr;
		size_t size = FormatMessageW(
			FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			nullptr,
			dwErrorCode,
			0,
			(WCHAR*)&wMsgBuf,
			0,
			nullptr
		);

		std::wstring wMsg(wMsgBuf, size);
		LocalFree(wMsgBuf);
		return wMsg;
	}

	INT DisplayMessageBoxA(LPCSTR text, LPCSTR caption)
	{
		INT msgBoxId = MessageBoxA(
			NULL,
			text,
			caption,
			MB_ICONWARNING | MB_CANCELTRYCONTINUE | MB_DEFBUTTON2
		);

		switch (msgBoxId)
		{
		case IDCANCEL:
			break;
		case IDTRYAGAIN:
			break;
		case IDCONTINUE:
			break;
		}

		return msgBoxId;
	}

	INT DisplayMessageBoxW(LPCWSTR text, LPCWSTR caption)
	{
		INT msgBoxId = MessageBoxW(
			NULL,
			text,
			caption,
			MB_ICONWARNING | MB_CANCELTRYCONTINUE | MB_DEFBUTTON2
		);

		switch (msgBoxId)
		{
		case IDCANCEL:
			break;
		case IDTRYAGAIN:
			break;
		case IDCONTINUE:
			break;
		}

		return msgBoxId;
	}

	INT DisplayErrorMessageBoxW(LPCWSTR caption)
	{
		LPWSTR lpMsg;
		FormatMessageW(
			FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			GetLastError(),
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPWSTR)&lpMsg,
			0,
			NULL
		);

		INT msgBoxId = MessageBoxW(NULL, lpMsg, caption, MB_OK);

		switch (msgBoxId)
		{
		case IDCANCEL:
			break;
		case IDTRYAGAIN:
			break;
		case IDCONTINUE:
			break;
		}

		return msgBoxId;
	}
}
