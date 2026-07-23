#pragma once

#if defined(_MSC_VER)
	#include <Windows.h>
#elif defined(__MINGW32__)
	#include <windows.h>
#else
	#error "No support for this one. Targetting Windows only."
#endif

// Controls exception handling.
// If you disable exceptions, then you're on your own, and expect the code to crash
#if !defined(SAFEHOOK_NO_EXCEPTIONS)
	#define SAFEHOOK_NO_EXCEPTIONS 0
#endif

#if !defined(SAFEHOOK_TEST)
	#define SAFEHOOK_TEST 0
#endif

#if defined(_M_X64) || defined(__x86_64__) || defined(__amd64__)
	#define SAFEHOOK_X64 1
	#define SAFEHOOK_X86 0
	#define SAFEHOOK_BY_ARCH(x86, x64) x64
#else
	#define SAFEHOOK_X86 1
	#define SAFEHOOK_X64 0
	#define SAFEHOOK_BY_ARCH(x86, x64) x86
#endif

#if defined(_MSC_VER)
	#define SAFEHOOK_FORCEINLINE __forceinline
#elif defined(__GNUC__) || defined(__clang__)
	#define SAFEHOOK_FORCEINLINE inline __attribute__((always_inline))
#else
	#define SAFEHOOK_FORCEINLINE inline
#endif

#if defined(_MSC_VER)
	#define ALIGNAS(x) __declspec(align(x))
#elif defined(__GNUC__) || defined(__clang__)
	#define ALIGNAS(x) __attribute__((aligned(x)))
#else
	#define ALIGNAS(x)
#endif

#if SAFEHOOK_X64
	#include "hde/hde64.h"
#else
	#include "hde/hde32.h"
#endif

#include <assert.h>
#include <new>
#include <stdio.h>
#include <Psapi.h>
#include <ProcessSnapshot.h>
#include <processthreadsapi.h>
#include <TlHelp32.h>
#include <initializer_list>

// All credits for function hooks goes to DarkByte

#if SAFEHOOK_X64
	typedef hde64s hde_s;
	#define HDE_DISASM(ptr, disasm) hde64_disasm(ptr, disasm)
#else
	typedef hde32s hde_s;
	#define HDE_DISASM(ptr, disasm) hde32_disasm(ptr, disasm)
#endif

namespace SafeHook
{
#if SAFEHOOK_X64
	static inline unsigned char asm_data[] =
	{
		0x9C,											// pushfq
		0x50,											// push rax
		0x48, 0x89, 0xE0,								// mov rax, rsp
		0x48, 0x83, 0xE4, 0xF0,							// and rsp, 0xFFFFFFFFFFFFFFF0
		0x48, 0x81, 0xEC, 0xA0, 0x02, 0x00, 0x00,		// sub rsp, 0x2A0
		0x0F, 0xAE, 0x44, 0x24, 0x20,					// fxsave [rsp + 0x20]
		0x48, 0x89, 0x9C, 0x24, 0x20, 0x02, 0x00, 0x00, // mov [rsp + 0x220], rbx
		0x48, 0x89, 0x8C, 0x24, 0x28, 0x02, 0x00, 0x00, // mov [rsp + 0x228], rcx
		0x48, 0x89, 0x94, 0x24, 0x30, 0x02, 0x00, 0x00, // mov [rsp + 0x230], rdx
		0x48, 0x89, 0xB4, 0x24, 0x38, 0x02, 0x00, 0x00, // mov [rsp + 0x238], rsi
		0x48, 0x89, 0xBC, 0x24, 0x40, 0x02, 0x00, 0x00, // mov [rsp + 0x240], rdi 
		0x48, 0x89, 0x84, 0x24, 0x48, 0x02, 0x00, 0x00, // mov [rsp + 0x248], rax
		0x48, 0x89, 0xAC, 0x24, 0x50, 0x02, 0x00, 0x00, // mov [rsp + 0x250], rbp
		0x4C, 0x89, 0x84, 0x24, 0x58, 0x02, 0x00, 0x00, // mov [rsp + 0x258], r8
		0x4C, 0x89, 0x8C, 0x24, 0x60, 0x02, 0x00, 0x00, // mov [rsp + 0x260], r9
		0x4C, 0x89, 0x94, 0x24, 0x68, 0x02, 0x00, 0x00, // mov [rsp + 0x268], r10
		0x4C, 0x89, 0x9C, 0x24, 0x70, 0x02, 0x00, 0x00, // mov [rsp + 0x270], r11
		0x4C, 0x89, 0xA4, 0x24, 0x78, 0x02, 0x00, 0x00, // mov [rsp + 0x278], r12
		0x4C, 0x89, 0xAC, 0x24, 0x80, 0x02, 0x00, 0x00, // mov [rsp + 0x280], r13
		0x4C, 0x89, 0xB4, 0x24, 0x88, 0x02, 0x00, 0x00, // mov [rsp + 0x288], r14
		0x4C, 0x89, 0xBC, 0x24, 0x90, 0x02, 0x00, 0x00, // mov [rsp + 0x290], r15
		0x48, 0x8D, 0x4C, 0x24, 0x20,					// lea rcx, [rsp + 0x20]
		0xE8, 0x80, 0x00, 0x00, 0x00,					// call $+0x80
		0x4C, 0x8B, 0xBC, 0x24, 0x90, 0x02, 0x00, 0x00, // mov r15, [rsp + 0x290]
		0x4C, 0x8B, 0xB4, 0x24, 0x88, 0x02, 0x00, 0x00, // mov r14, [rsp + 0x288]
		0x4C, 0x8B, 0xAC, 0x24, 0x80, 0x02, 0x00, 0x00, // mov r13, [rsp + 0x280]
		0x4C, 0x8B, 0xA4, 0x24, 0x78, 0x02, 0x00, 0x00, // mov r12, [rsp + 0x278]
		0x4C, 0x8B, 0x9C, 0x24, 0x70, 0x02, 0x00, 0x00, // mov r11, [rsp + 0x270]
		0x4C, 0x8B, 0x94, 0x24, 0x68, 0x02, 0x00, 0x00, // mov r10, [rsp + 0x268]
		0x4C, 0x8B, 0x8C, 0x24, 0x60, 0x02, 0x00, 0x00, // mov r9, [rsp + 0x260]
		0x4C, 0x8B, 0x84, 0x24, 0x58, 0x02, 0x00, 0x00, // mov r8, [rsp + 0x258]
		0x48, 0x8B, 0xAC, 0x24, 0x50, 0x02, 0x00, 0x00, // mov rbp, [rsp + 0x250]
		0x48, 0x8B, 0xBC, 0x24, 0x40, 0x02, 0x00, 0x00, // mov rdi, [rsp + 0x240]
		0x48, 0x8B, 0xB4, 0x24, 0x38, 0x02, 0x00, 0x00, // mov rsi, [rsp + 0x238]
		0x48, 0x8B, 0x94, 0x24, 0x30, 0x02, 0x00, 0x00, // mov rdx, [rsp + 0x230]
		0x48, 0x8B, 0x8C, 0x24, 0x28, 0x02, 0x00, 0x00, // mov rcx, [rsp + 0x228]
		0x48, 0x8B, 0x9C, 0x24, 0x20, 0x02, 0x00, 0x00, // mov rbx, [rsp + 0x220]
		0x0F, 0xAE, 0x4C, 0x24, 0x20,					// fxrstor [rsp + 0x20]
		0x48, 0x8B, 0xA4, 0x24, 0x48, 0x02, 0x00, 0x00, // mov rsp, [rsp + 0x248]
		0x58,											// pop rax
		0x9D,											// popfq
		0xC3,											// ret
	};

#else
	static inline unsigned char asm_data[] =
	{
		0x9C,										// pushfd
		0x50,										// push eax
		0x89, 0xE0,									// mov eax, esp
		0x83, 0xE4, 0xF0,							// and esp, 0xFFFFFFF0
		0x81, 0xEC, 0x20, 0x02, 0x00, 0x00,			// sub esp, 0x220
		0x0F, 0xAE, 0x04, 0x24,						// fxsave [esp] 
		0x89, 0x9C, 0x24, 0x00, 0x02, 0x00, 0x00,	// mov [esp + 0x200], ebx
		0x89, 0x8C, 0x24, 0x04, 0x02, 0x00, 0x00,	// mov [esp + 0x204], ecx
		0x89, 0x94, 0x24, 0x08, 0x02, 0x00, 0x00,	// mov [esp + 0x208], edx
		0x89, 0xB4, 0x24, 0x0C, 0x02, 0x00, 0x00,	// mov [esp + 0x20C], esi
		0x89, 0xBC, 0x24, 0x10, 0x02, 0x00, 0x00,	// mov [esp + 0x210], edi
		0x89, 0x84, 0x24, 0x14, 0x02, 0x00, 0x00,	// mov [esp + 0x214], eax
		0x89, 0xAC, 0x24, 0x18, 0x02, 0x00, 0x00,	// mov [esp + 0x218], ebp
		0x89, 0xE0,									// mov eax, esp
		0x50,										// push eax
		0xE8, 0x3B, 0x00, 0x00, 0x00,				// call $+0x3B
		0x83, 0xC4, 0x04,							// add esp, 4
		0x8B, 0xAC, 0x24, 0x18, 0x02, 0x00, 0x00,	// mov ebp, [esp + 0x218]
		0x8B, 0xBC, 0x24, 0x10, 0x02, 0x00, 0x00,	// mov edi, [esp + 0x210]
		0x8B, 0xB4, 0x24, 0x0C, 0x02, 0x00, 0x00,	// mov esi, [esp + 0x20C]
		0x8B, 0x94, 0x24, 0x08, 0x02, 0x00, 0x00,	// mov edx, [esp + 0x208]
		0x8B, 0x8C, 0x24, 0x04, 0x02, 0x00, 0x00,	// mov ecx, [esp + 0x204]
		0x8B, 0x9C, 0x24, 0x00, 0x02, 0x00, 0x00,	// mov ebx, [esp + 0x200] 
		0x0F, 0xAE, 0x0C, 0x24,						// fxrstor [esp]
		0x8B, 0xA4, 0x24, 0x14, 0x02, 0x00, 0x00,	// mov esp, [esp + 0x214]
		0x58,										// pop eax
		0x9D,										// popfd
		0xC3										// ret
	};
#endif
#if SAFEHOOK_NO_EXCEPTIONS
	class Exception
	{
	public:
		Exception() = default;
		Exception(const char* msg, const char* file, unsigned int line) {};
		Exception(const Exception&) = default;
		Exception(Exception&&) noexcept = default;

		~Exception() = default;

		Exception& operator=(const Exception& other) = default;
		Exception& operator=(Exception&& other) noexcept = default;

		const char* what() const { return ""; }
		int line() const { return -1; }
		const char* file() const { return ""; }

		void DoFormat(const char* fmt, ...) {}
	};
#else
	class Exception
	{
		char* m_msg;
		const char* m_file;
		unsigned int m_line;

		void AllocateString(const char* msg)
		{
			size_t len = strlen(msg) + 1;
			m_msg = new char[len];
			strcpy_s(m_msg, len, msg);
		}

		void FreeString()
		{
			if (m_msg)
			{
				delete[] m_msg;
				m_msg = nullptr;
			}
		}

		void CopyFrom(const Exception& other)
		{
			m_line = other.m_line;
			AllocateString(other.m_msg);
		}

		void MoveFrom(Exception&& other) noexcept
		{
			m_line = other.m_line;
			m_msg = other.m_msg;
			other.m_msg = nullptr;
		}

		void MoveFrom(Exception& other) noexcept
		{
			m_line = other.m_line;
			m_msg = other.m_msg;
			other.m_msg = nullptr;
		}

		void FormatMsg(const char* fmt, va_list va)
		{
			int length = _vscprintf(fmt, va) + 1;
			m_msg = new char[length];

			vsnprintf_s(m_msg, length, length - 1, fmt, va);
		}
	public:
		Exception(const char* msg, const char* file, unsigned int line) : m_line(line), m_file(file)
		{
			if (msg)
				AllocateString(msg);
		}

		Exception(const Exception& other)
		{
			CopyFrom(other);
		}

		Exception(Exception&& other) noexcept
		{
			MoveFrom(std::move(other));
		}

		~Exception()
		{
			FreeString();
		}

		Exception& operator=(const Exception& other)
		{
			if (this != &other)
			{
				FreeString();
				CopyFrom(other);
			}
			return *this;
		}

		Exception& operator=(Exception&& other) noexcept
		{
			if (this != &other)
			{
				FreeString();
				MoveFrom(std::move(other));
			}
			return *this;
		}

		const char* what() const { return m_msg; }
		int line() const { return m_line; }
		const char* file() const { return m_file; }

		static inline char ExceptionBuffer[512];

		void DoFormat(const char* format, ...)
		{
			va_list va;
			va_start(va, format);

			FormatMsg(format, va);

			va_end(va);
		}
	};
#endif

#if SAFEHOOK_NO_EXCEPTIONS
	inline void ReportException(const Exception& e) {}
	inline void SilentReport(const char* fmt, ...) {}
#else
	inline void ReportException(const Exception& e)
	{
		Exception::ExceptionBuffer[0] = 0;
		sprintf_s(Exception::ExceptionBuffer, "SafeHook Exception in %s: %s (line %d)\n", e.file(), e.what(), e.line());
		MessageBoxA(nullptr, Exception::ExceptionBuffer, "SafeHook", MB_ICONERROR | MB_OK);

		OutputDebugStringA(Exception::ExceptionBuffer);
	}

	inline void SilentReport(const char* fmt, ...)
	{
		va_list va;
		va_start(va, fmt);

		memset(Exception::ExceptionBuffer, 0, sizeof(Exception::ExceptionBuffer));
		
		vsprintf_s(Exception::ExceptionBuffer, fmt, va);

		OutputDebugStringA(Exception::ExceptionBuffer);

		va_end(va);
	}
#endif

#if SAFEHOOK_NO_EXCEPTIONS
	#define SAFEHOOK_THROW(msg) do { std::abort(); } while(0)
	#define SAFEHOOK_THROW_FORMAT(msg, ...) do { std::abort(); } while(0)
	#define SAFEHOOK_REPORT_HERE(msg, ...) do { std::abort(); } while(0)
	#define SAFEHOOK_CATCH(e) catch (const SafeHook::Exception& e) { std::abort(); }
	#define SAFEHOOK_CATCH_RET(e) catch (const SafeHook::Exception& e) { std::abort(); return; }
#else
	#define SAFEHOOK_THROW(msg) throw SafeHook::Exception(msg, __FILE__, __LINE__)
	#define SAFEHOOK_THROW_FORMAT(msg, ...) do { SafeHook::Exception except(nullptr, __FILE__, __LINE__); except.DoFormat(msg, __VA_ARGS__); throw except; } while(0)
	// Also reports function where the exception was thrown, and the line number
	#define SAFEHOOK_REPORT_HERE(msg, ...) SAFEHOOK_THROW_FORMAT(__FUNCTION__ ## ": " ## msg, __VA_ARGS__)
	#define SAFEHOOK_CATCH(e) catch (const SafeHook::Exception& e) { SafeHook::ReportException(e); } 
	#define SAFEHOOK_CATCH_RET(e) catch (const SafeHook::Exception& e) { SafeHook::ReportException(e); return; }
#endif

#define CHECK_ERROR(disasm) if (disasm.flags & F_ERROR) \
	{													\
		if (disasm.flags & F_ERROR_LENGTH) SAFEHOOK_THROW("Disasm: Length Error!");	\
		else if (disasm.flags & F_ERROR_OPCODE) SAFEHOOK_THROW("Disasm: Opcode Error!");	\
		else if (disasm.flags & F_ERROR_OPERAND) SAFEHOOK_THROW("Disasm: Operand Error!");	\
		else if (disasm.flags & F_ERROR_LOCK) SAFEHOOK_THROW("Disasm: Lock Error!");	\
		else SAFEHOOK_THROW("Disasm: Unknown Error!");	\
	}													

	inline size_t align(size_t length, size_t alignment)
	{
		return (length + alignment - 1) & ~(alignment - 1);
	}

	inline size_t getAllocationGranularity()
	{
		SYSTEM_INFO sysInfo;
		GetSystemInfo(&sysInfo);

		return sysInfo.dwAllocationGranularity;
	}

#if SAFEHOOK_X86
	inline constexpr size_t g_JmpInstructionSize = 5;
#else
	inline constexpr size_t g_JmpInstructionSize = 14; // 14 bytes for the mov rax, imm64 + jmp rax instructions
#endif
	inline constexpr size_t g_RelativeJmpInstructionSize = 5;

	class SafeAddress;

	inline bool CheckValidAddress(SafeAddress x);

	class SafeAddress
	{
		uintptr_t m_address;
	public:
		constexpr SafeAddress() : m_address(0) {}
		constexpr SafeAddress(uintptr_t address) : m_address(address) {}
		constexpr SafeAddress(const void* address) : m_address((uintptr_t)address) {}

		const uintptr_t get() const { return m_address; }
		void add(size_t offset) { m_address += offset; }

		void set(uintptr_t address) { m_address = address; }
		void set(const void* address) { m_address = (uintptr_t)address; }

		uintptr_t operator+(size_t offset) const { return m_address + offset; }
		uintptr_t operator-(size_t offset) const { return m_address - offset; }
		uintptr_t operator-(const SafeAddress& other) const { return m_address - other.m_address; }
		uintptr_t operator+(const SafeAddress& other) const { return m_address + other.m_address; }

		SafeAddress& operator+=(size_t offset) { m_address += offset; return *this; }
		SafeAddress& operator-=(size_t offset) { m_address -= offset; return *this; }
		SafeAddress& operator+=(const SafeAddress& other) { m_address += other.m_address; return *this; }
		SafeAddress& operator-=(const SafeAddress& other) { m_address -= other.m_address; return *this; }

		SafeAddress& operator=(const uintptr_t& address) { m_address = address; return *this; }
		SafeAddress& operator=(const void* address) { m_address = (uintptr_t)address; return *this; }
		SafeAddress& operator=(const SafeAddress& other) { m_address = other.m_address; return *this; }

		bool operator==(const SafeAddress& other) const { return m_address == other.m_address; }
		bool operator!=(const SafeAddress& other) const { return m_address != other.m_address; }

		bool DistRangeOf(const SafeAddress& to, size_t range) const
		{
			uintptr_t distance = m_address > to.m_address ? m_address - to.m_address : to.m_address - m_address;

			return distance <= range;
		}

		bool IsValid() const { return CheckValidAddress(*this); }
	};

	inline bool CheckValidAddress(SafeAddress address)
	{
		if (!address.get()) // address == nullptr
			return false;

		MEMORY_BASIC_INFORMATION mbi;
		if (VirtualQuery((LPCVOID)address.get(), &mbi, sizeof(mbi)) == 0)
			return false;

		return (mbi.State == MEM_COMMIT) && ((mbi.Protect & PAGE_NOACCESS) == 0);
	}

	template <typename T>
	class Vector
	{
		T* m_data = nullptr; // first element
		T* m_end = nullptr; // allocated end
		T* m_last = nullptr; // last element

		using isPtr = std::is_pointer<T>::value_type;

		// Allocates memory for the vector
		// Will potentially grow exponentially if newCapacity is 0
		void reallocate(size_t newCapacity = 0)
		{
			if (!capacity() && !newCapacity)
				newCapacity = 4; // default capacity
				
			T* oldData = m_data;
			if (!newCapacity)
				newCapacity = capacity() * 2; // doing x^2 growth isn't the best idea, x*2 is better for RAM usage

			size_t sz = size();

			m_data = new T[newCapacity];
			if (oldData)
			{
				MoveElems(m_data, oldData, sz);
				delete[] oldData;
			}

			m_last = m_data + sz;
			m_end = m_data + newCapacity;
		}

		void destroy()
		{
			if (m_data)
			{
				delete[] m_data;
				m_data = nullptr;
				m_last = nullptr;
				m_end = nullptr;
			}
		}

		void DestructElems(T* begin, T* end)
		{
			if (!isPtr())
			{
				for (T* it = begin; it != end; ++it)
					it->~T();
			}
		}

		void ConstructElems(T* begin, T* end)
		{
			if (!isPtr())
			{
				for (T* it = begin; it != end; ++it)
					new(it) T();
			}
		}

		void ConstructElems(T* begin, T* end, const T& value)
		{
			if (!isPtr())
			{
				for (T* it = begin; it != end; ++it)
					new(it) T(value);
			}
		}

		void CopyElems(T* dest, const T* src, size_t count)
		{
			if (!isPtr())
			{
				for (size_t i = 0; i < count; ++i)
					new(dest + i) T(src[i]);
			}
			else
			{
				memcpy(dest, src, count * sizeof(T));
			}
		}

		void MoveElems(T* dest, const T* src, size_t count)
		{
			if (!isPtr())
			{
				for (size_t i = 0; i < count; ++i)
					new(dest + i) T(std::move(src[i]));
			}
			else
			{
				memcpy(dest, src, count * sizeof(T));
			}
		}
	public:
		Vector() {}
		Vector(size_t capacity) : m_data(nullptr), m_end(nullptr), m_last(nullptr)
		{
			reallocate(capacity);
		}

		Vector(const Vector& other) : m_data(nullptr), m_end(nullptr), m_last(nullptr)
		{
			reallocate(other.capacity());
			CopyElems(m_data, other.m_data, other.size());
			m_last = m_data + other.size();
		}

		Vector(Vector&& other) noexcept : m_data(other.m_data), m_end(other.m_end), m_last(other.m_last)
		{
			other.m_data = nullptr;
			other.m_end = nullptr;
			other.m_last = nullptr;
		}

		Vector(std::initializer_list<T> init) : m_data(nullptr), m_end(nullptr), m_last(nullptr)
		{
			reallocate(init.size());
			CopyElems(m_data, init.begin(), init.size());
			m_last = m_data + init.size();
		}

		~Vector()
		{
			DestructElems(m_data, m_last);
			destroy();
		}

		Vector& operator=(const Vector& other)
		{
			if (this != &other)
			{
				destroy();
				reallocate(other.capacity());
				CopyElems(m_data, other.m_data, other.size());
				m_last = m_data + other.size();
			}
			return *this;
		}

		Vector& operator=(Vector&& other) noexcept
		{
			if (this != &other)
			{
				destroy();
				m_data = other.m_data;
				m_end = other.m_end;
				m_last = other.m_last;

				other.m_data = nullptr;
				other.m_end = nullptr;
				other.m_last = nullptr;
			}
			return *this;
		}

		Vector& operator=(std::initializer_list<T> list)
		{
			destroy();
			reallocate(list.size());
			CopyElems(m_data, list.begin(), list.size());

			m_last = m_data + list.size();
			return *this;
		}

		void clear()
		{
			DestructElems(m_data, m_last);
			m_last = m_data;
		}

		size_t capacity() const { return m_end - m_data; }
		size_t size() const { return m_last - m_data; }
		bool empty() const { return size() == 0; }
		
		void reserve(size_t newCapacity)
		{
			if (newCapacity > capacity())
				reallocate(newCapacity);
		}

		void resize(size_t newSize)
		{
			if (newSize > capacity())
				reallocate(newSize);
			if (newSize > size())
				m_last = m_data + newSize; // Increase size without constructing new elements
			else if (newSize < size())
				DestructElems(m_data + newSize, m_last);

			m_last = m_data + newSize;
		}

		void push_back(const T& value)
		{
			if (size() >= capacity())
				reallocate();

			new(m_last) T(value);
			++m_last;
		}

		void push_back(T&& value)
		{
			if (size() >= capacity())
				reallocate();

			new(m_last) T(std::move(value));

			++m_last;
		}

		void pop_back()
		{
			if (!empty())
			{
				--m_last;
				DestructElems(m_last, m_last + 1);
			}
		}

		void insert(size_t index, const T& value)
		{
			if (index > size())
				return; 

			if (size() >= capacity())
				reallocate();

			MoveElems(m_data + index + 1, m_data + index, size() - index);
			new(m_data + index) T(value);
			++m_last;
		}

		void insert(size_t index, T&& value)
		{
			if (index > size())
				return;

			if (size() >= capacity())
				reallocate();

			MoveElems(m_data + index + 1, m_data + index, size() - index);
			new(m_data + index) T(std::move(value));
			++m_last;
		}

		void fill(const T& value)
		{
			for (T* it = m_data; it != m_last; ++it)
				*it = value;
		}

		void fill(T&& value)
		{
			for (T* it = m_data; it != m_last; ++it)
				*it = std::move(value);
		}

		void fill(const T& value, size_t count)
		{
			if (count > capacity())
				reallocate(count);

			for (size_t i = 0; i < count; ++i)
				new(m_data + i) T(value);

			m_last = m_data + count;
		}

		T* find(const T& value)
		{
			for (T* it = m_data; it != m_last; ++it)
			{
				if (*it == value)
					return it;
			}
			return nullptr;
		}

		template <typename Func>
		T* find_if(Func predicate)
		{
			for (T* it = m_data; it != m_last; ++it)
			{
				if (predicate(*it))
					return it;
			}
			return nullptr;
		}

		template <typename Func>
		void sort_by(Func comparator)
		{
			for (T* i = m_data; i != m_last; ++i)
			{
				for (T* j = i + 1; j != m_last; ++j)
				{
					if (comparator(*j, *i))
					{
						std::swap(*i, *j);
					}
				}
			}
		}

		template <typename Func>
		void for_each(Func func)
		{
			for (T* it = m_data; it != m_last; ++it)
			{
				func(*it);
			}
		}

		void erase(size_t index)
		{
			if (index >= size())
				return;

			DestructElems(m_data + index, m_data + index + 1);
			MoveElems(m_data + index, m_data + index + 1, size() - index - 1);

			--m_last;
		}

		void erase(T* element)
		{
			if (element < m_data || element >= m_last)
				return;

			size_t index = element - m_data;
			erase(index);
		}

		T* begin() { return m_data; }
		const T* begin() const { return m_data; }

		T* end() { return m_last; }
		const T* end() const { return m_last; }

		T& operator[](size_t index) { return m_data[index]; }
		const T& operator[](size_t index) const { return m_data[index]; }
	};

	inline bool EnumerateThreads(Vector<DWORD>& threadIds)
	{
		DWORD curProcessId = GetCurrentProcessId();
		DWORD curThreadId = GetCurrentThreadId();

		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE)
			return false;

		THREADENTRY32 te;
		te.dwSize = sizeof(THREADENTRY32);

		if (Thread32First(hSnapshot, &te))
		{
			while ((te.th32OwnerProcessID != curProcessId) && Thread32Next(hSnapshot, &te)) { (void)0; }; // Skip threads that don't belong to the current process

			do
			{
				if (te.th32ThreadID != curThreadId)
					threadIds.push_back(te.th32ThreadID);
				
			} while (Thread32Next(hSnapshot, &te));
		}

		CloseHandle(hSnapshot);

		return true;
	}

	inline void SuspendThreads(Vector<DWORD>& threadIds)
	{
		for (int i = threadIds.size() - 1; i >= 0; --i)
		{
			DWORD threadId = threadIds[i];
			HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
			if (hThread)
			{
				if (SuspendThread(hThread) == -1)
				{
					threadIds.erase(i); // Remove the thread ID from the list if it can't be opened
					CloseHandle(hThread);
					continue;
				}
				CloseHandle(hThread);
			}
			else
			{
				threadIds.erase(i); // Remove the thread ID from the list if it can't be opened
			}
		}
	}

	inline void ResumeThreads(Vector<DWORD>& threadIds)
	{
		for (int i = threadIds.size() - 1; i >= 0; --i)
		{
			DWORD threadId = threadIds[i];
			HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
			if (hThread)
			{
				ResumeThread(hThread);
				CloseHandle(hThread);
			}
		}
	}

	inline void RedirectThreads(const Vector<DWORD>& threadIds, SafeAddress target, size_t size, SafeAddress trampoline)
	{
		bool doBreak = false;
		for (int i = threadIds.size() - 1; i >= 0; --i)
		{
			DWORD threadId = threadIds[i];
			HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, threadId);
			if (hThread)
			{
				CONTEXT ctx;
				ctx.ContextFlags = CONTEXT_CONTROL;
				if (GetThreadContext(hThread, &ctx))
				{
#if SAFEHOOK_X64
					uintptr_t& ip = ctx.Rip;
#else
					DWORD& ip = ctx.Eip;
#endif
					// If a thread is suspended mid-prologue, recalculate its instruction pointer offset inside the trampoline
					if (ip >= target.get() && ip < (target + size))
					{
						uintptr_t offset = ip - target.get();
						ip = trampoline + offset;
						SetThreadContext(hThread, &ctx);
					}
				}
				CloseHandle(hThread);
			}
		}
	}

	// Redirects all threads in the current process to a trampoline if they are currently executing inside the target function. Assuming the target function won't be called again after this function is called.
	inline void ThreadRedirect(SafeAddress target, size_t size, SafeAddress trampoline)
	{
		DWORD curThreadId = GetCurrentThreadId();
		DWORD curProcessId = GetCurrentProcessId();

		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE)
			SAFEHOOK_THROW("Failed to create thread snapshot!");

		THREADENTRY32 te;
		te.dwSize = sizeof(THREADENTRY32);

		if (Thread32First(hSnapshot, &te))
		{
			while (te.th32OwnerProcessID != curProcessId && Thread32Next(hSnapshot, &te)) { (void)0; }; // Skip threads that don't belong to the current process

			do
			{
				if (te.th32ThreadID != curThreadId)
				{
					HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
					if (hThread)
					{
						SuspendThread(hThread);

						CONTEXT ctx;
						ctx.ContextFlags = CONTEXT_CONTROL;
						if (GetThreadContext(hThread, &ctx))
						{
#if SAFEHOOK_X64
							uintptr_t& ip = ctx.Rip;
#else
							DWORD& ip = ctx.Eip;
#endif
							// If a thread is suspended mid-prologue, recalculate its instruction pointer offset inside the trampoline
							if (ip >= target.get() && ip < (target + size))
							{
								uintptr_t offset = ip - target.get();
								ip = trampoline + offset;
								SetThreadContext(hThread, &ctx);
							}
						}
						ResumeThread(hThread);
						CloseHandle(hThread);
					}
				}
			} while (Thread32Next(hSnapshot, &te));
		}
		CloseHandle(hSnapshot);
	}

	inline unsigned int GetDistanceTypeSize(SafeAddress from, SafeAddress to)
	{
		size_t distance = to.get() > from.get() ? to.get() - from.get() : from.get() - to.get(); // absolute distance
		if (distance <= 0x7F)
			return sizeof(uint8_t);
		else if (distance <= 0x7FFFFFFF)
			return sizeof(uint32_t);
		else
			return sizeof(uint64_t);
	}

	class PageController
	{
	public:
		static inline constexpr size_t PAGE_SIZE = 0x1000;
		static inline size_t VIRTUAL_PAGE_SIZE = getAllocationGranularity();
	protected:
		class Page
		{
		protected:
			struct Block
			{
				void* m_baseptr;
				size_t m_size;
				size_t m_alignment;

				Block* m_pNext, *m_pPrev;

				Block(void* baseptr, size_t size, size_t alignment) : m_baseptr(baseptr), m_size(size), m_alignment(alignment), m_pNext(nullptr), m_pPrev(nullptr) {}

				void chain(Block* pNext, Block* pPrev)
				{
					m_pNext = pNext;
					m_pPrev = pPrev;

					if (pNext)
						pNext->m_pPrev = this;

					if (pPrev)
						pPrev->m_pNext = this;
				}

				void unchain()
				{
					if (m_pNext)
						m_pNext->m_pPrev = m_pPrev;

					if (m_pPrev)
						m_pPrev->m_pNext = m_pNext;

					m_pNext = nullptr;
					m_pPrev = nullptr;
				}
			};

			void chainBlock(Block* pBlock)
			{
				if (!m_pFirstBlock)
				{
					m_pFirstBlock = pBlock;
					m_pLastBlock = pBlock;

					pBlock->m_pNext = nullptr;
					pBlock->m_pPrev = nullptr;
				}
				else
				{
					pBlock->chain(nullptr, m_pLastBlock);

					m_pLastBlock = pBlock;
				}
			}

			void unchainBlock(Block* pBlock)
			{
				if (pBlock == m_pFirstBlock)
					m_pFirstBlock = pBlock->m_pNext;

				if (pBlock == m_pLastBlock)
					m_pLastBlock = pBlock->m_pPrev;

				pBlock->unchain();
			}

			void* m_base;
			void* m_nextFree;
			void* m_end;

			Block* m_pFirstBlock, * m_pLastBlock;
		public:
			Page() : m_base(nullptr), m_nextFree(nullptr), m_end(nullptr), m_pFirstBlock(nullptr), m_pLastBlock(nullptr) {}
			Page(void* base, size_t size)
			{
				init(base, size);
			}

			Page(const Page& other) noexcept
			{
				m_base = other.m_base;
				m_nextFree = other.m_nextFree;
				m_end = other.m_end;
				m_pFirstBlock = other.m_pFirstBlock;
				m_pLastBlock = other.m_pLastBlock;			
			}

			Page(Page&& other)
			{
				if (this != &other)
				{
					m_base = other.m_base;
					m_nextFree = other.m_nextFree;
					m_end = other.m_end;
					m_pFirstBlock = other.m_pFirstBlock;
					m_pLastBlock = other.m_pLastBlock;

					other.m_base = nullptr;
					other.m_nextFree = nullptr;
					other.m_end = nullptr;
					other.m_pFirstBlock = nullptr;
					other.m_pLastBlock = nullptr;
				}
			}

			Page& operator=(const Page& other) noexcept
			{
				m_base = other.m_base;
				m_nextFree = other.m_nextFree;
				m_end = other.m_end;
				m_pFirstBlock = other.m_pFirstBlock;
				m_pLastBlock = other.m_pLastBlock;
			}

			Page& operator=(Page&& other)
			{
				if (this != &other)
				{
					m_base = other.m_base;
					m_nextFree = other.m_nextFree;
					m_end = other.m_end;
					m_pFirstBlock = other.m_pFirstBlock;
					m_pLastBlock = other.m_pLastBlock;

					other.m_base = nullptr;
					other.m_nextFree = nullptr;
					other.m_end = nullptr;
					other.m_pFirstBlock = nullptr;
					other.m_pLastBlock = nullptr;
				}
				return *this;
			}

			size_t size() const { return (uintptr_t)m_end - (uintptr_t)m_base; }
			Block* firstBlock() const { return m_pFirstBlock; }
			Block* lastBlock() const { return m_pLastBlock; }

			void init(void* base, size_t size)
			{
				m_base = m_nextFree = base;
				m_end = (void*)((uintptr_t)base + size);

				m_pFirstBlock = m_pLastBlock = nullptr;
			}

			void deinit()
			{
				for (Block* pBlock = m_pFirstBlock; pBlock; )
				{
					Block* pNext = pBlock->m_pNext;

					delete pBlock;
					pBlock = pNext;
				}

				m_pFirstBlock = m_pLastBlock = nullptr;
				m_base = m_nextFree = m_end = nullptr;
			}

			void* getNextFree() const { return m_nextFree; }

			void* alloc(size_t size, size_t alignment = SAFEHOOK_BY_ARCH(32, 64))
			{
				if (!m_base)
					SAFEHOOK_REPORT_HERE("Page is not initialized!");

				uintptr_t current = (uintptr_t)m_nextFree;
				if (align(current + size, alignment) > (uintptr_t)m_end) // out of memory
					return nullptr;

				m_nextFree = (void*)align(current + size, alignment);

				Block* pBlock = new Block((void*)current, size, alignment);
				chainBlock(pBlock);

				return pBlock->m_baseptr;
			}

			void free(void* ptr)
			{
				if (!ptr)
					return;

				if (!m_base) // not that critical to throw an exception here
					return;

				if (ptr < m_base || ptr >= m_end)
				{
					SilentReport("It's not our pointer: %p %p\n", ptr, m_base);
					return;
				}

				for (Block* pBlock = m_pFirstBlock; pBlock; pBlock = pBlock->m_pNext)
				{
					if (pBlock->m_baseptr == ptr)
					{
						if (pBlock == m_pLastBlock)
							m_nextFree = pBlock->m_baseptr;

						unchainBlock(pBlock);
						delete pBlock;
						return;
					}
				}
			}

			friend class PageController;
			friend class AllocationRegion;
		};

		class AllocationRegion
		{
		protected:
			void* m_baseAddress;
			size_t m_size;

			LONG m_allocRefCount;

			Vector<Page> m_pages;
		public:
			AllocationRegion() : m_baseAddress(nullptr), m_size(0) {}
			~AllocationRegion()
			{
				deinit();
			}

			bool init(size_t size)
			{
				if (!size)
					return false;

				m_baseAddress = VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				if (!m_baseAddress)
					return false;

				m_size = size;
				m_allocRefCount = 0;

				m_pages.reserve(size / PAGE_SIZE);
				for (size_t i = 0; i < size / PAGE_SIZE; ++i)
				{
					Page page;
					page.init((void*)align((uintptr_t)m_baseAddress + i * PAGE_SIZE, PAGE_SIZE), PAGE_SIZE);

					m_pages.push_back(std::move(page));
				}

				return true;
			}

#if SAFEHOOK_X64
			// can be used to initialize region near the module or something else
			bool initNear(SafeAddress from, size_t size)
			{
				if (!size)
					return false;

				// while (range(from, base) <= 0x7FFF0000) { ...; base += mbi.RegionSize; }
				for (SafeAddress base = from; from.DistRangeOf(base, 0x7FFF0000); )
				{
					MEMORY_BASIC_INFORMATION mbi{0};
					if (!VirtualQuery((LPCVOID)base.get(), &mbi, sizeof(mbi)))
						return false;

					if (mbi.State == MEM_FREE && mbi.RegionSize >= size)
					{
						m_baseAddress = VirtualAlloc((LPVOID)base.get(), size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
						if (!m_baseAddress)
							return false;

						m_size = size;
						m_allocRefCount = 0;

						m_pages.reserve(size / PAGE_SIZE);
						for (size_t i = 0; i < size / PAGE_SIZE; ++i)
						{
							Page page;
							page.init((void*)align((uintptr_t)m_baseAddress + i * PAGE_SIZE, PAGE_SIZE), PAGE_SIZE);

							m_pages.push_back(std::move(page));
						}

						return true;
					}

					base += (uintptr_t)mbi.RegionSize;
				}

				return false;
			}
#endif

			void deinit()
			{
				for (Page& page : m_pages)
					page.deinit();

				m_pages.clear();

				if (m_baseAddress)
					VirtualFree(m_baseAddress, 0, MEM_RELEASE);

				m_baseAddress = nullptr;
				m_size = 0;
			}

			void* alloc(size_t size, size_t alignment = SAFEHOOK_BY_ARCH(32, 64))
			{
				for (Page& page : m_pages)
				{
					void* ptr = page.alloc(size, alignment);
					if (ptr)
					{
						m_allocRefCount++;
						return ptr;
					}
				}
				return nullptr;
			}
#if SAFEHOOK_X64
			bool checkDistance2GB(SafeAddress from) const
			{
				if (!m_baseAddress)
					return false;

				return GetDistanceTypeSize(from, SafeAddress(m_baseAddress)) <= sizeof(uint32_t);
			}
#endif

			void free(void* ptr)
			{
				if (!ptr)
					return;

				for (Page& page : m_pages)
				{
					if (ptr >= page.m_base && ptr < page.m_end)
					{
						page.free(ptr);
						m_allocRefCount--;
						return;
					}
				}
			}

			friend class PageController;
		};

		Vector<AllocationRegion*> m_regions;
#if SAFEHOOK_X64
		Vector<AllocationRegion*> m_nearRegions;
#endif
	public:
		PageController() {}
		~PageController()
		{
			for (AllocationRegion* pRegion : m_regions)
			{
				pRegion->deinit();
				delete pRegion;
			}

#if SAFEHOOK_X64
			for (AllocationRegion* pRegion : m_nearRegions)
			{
				pRegion->deinit();
				delete pRegion;
			}
#endif
		}

		void* alloc(size_t size, size_t alignment = SAFEHOOK_BY_ARCH(32, 64))
		{
			if (!size)
				return nullptr;

			for (AllocationRegion* pRegion : m_regions)
			{
				void* ptr = pRegion->alloc(size, alignment);
				if (ptr)
					return ptr;
			}

			AllocationRegion* pRegion = new AllocationRegion();
			if (!pRegion->init(VIRTUAL_PAGE_SIZE))
			{
				delete pRegion;
				SAFEHOOK_THROW_FORMAT("Could not even allocate page in whole virtual memory space, huh???? %zu", size);
				return nullptr;
			}

			m_regions.push_back(pRegion);
			return pRegion->alloc(size, alignment);
		}
#if SAFEHOOK_X64
		void* allocNear(SafeAddress from, size_t size, size_t alignment = SAFEHOOK_BY_ARCH(32, 64))
		{
			if (!size)
				return nullptr;

			for (AllocationRegion* pRegion : m_nearRegions)
			{
				if (pRegion->checkDistance2GB(from))
				{
					void* ptr = pRegion->alloc(size, alignment);
					if (ptr)
						return ptr;
				}
			}

			AllocationRegion* pRegion = new AllocationRegion();
			if (!pRegion->initNear(from, VIRTUAL_PAGE_SIZE))
			{
				delete pRegion;
				SilentReport("Could not allocate near base page, maybe try allocating in whole virtual memory space? %p\n", from.get());
				return nullptr;
			}

			m_nearRegions.push_back(pRegion);
			return pRegion->alloc(size, alignment);
		}
#endif

		void release(void* ptr)
		{
			if (!ptr)
				return;

			for (AllocationRegion*& pRegion : m_regions)
			{
				if (ptr >= pRegion->m_baseAddress && ptr < (void*)((uintptr_t)pRegion->m_baseAddress + pRegion->m_size))
				{
					pRegion->free(ptr);
					if (pRegion->m_allocRefCount == 0)
					{
						pRegion->deinit();
						m_regions.erase(&pRegion);
						delete pRegion;
					}
					return;
				}
			}
#if SAFEHOOK_X64 // only x64 has near allocation, not critical to check for x86
			for (AllocationRegion*& pRegion : m_nearRegions)
			{
				if (ptr >= pRegion->m_baseAddress && ptr < (void*)((uintptr_t)pRegion->m_baseAddress + pRegion->m_size))
				{
					pRegion->free(ptr);
					if (pRegion->m_allocRefCount == 0)
					{
						pRegion->deinit();
						m_nearRegions.erase(&pRegion);
						delete pRegion;
					}
					return;
				}
			}
#endif
		}

#if SAFEHOOK_X64
		// use it to have a region for hooking into specific module
		AllocationRegion* allocRegionMod(void* base, size_t size)
		{
			AllocationRegion* pRegion = new AllocationRegion();
			if (!pRegion->initNear(base, size))
			{
				delete pRegion;
				SilentReport("Oh fiddlesticks! %p\n", base);
				return nullptr;
			}

			m_nearRegions.push_back(pRegion); // still track it, shall we?

			return pRegion;
		}
#endif
	};

	inline PageController g_pageController;

	class scoped_unprotect
	{
		SafeAddress address;
		size_t size;
		DWORD old_protect;
	public:
		scoped_unprotect() : old_protect(0), address(uintptr_t(0)), size(0) {}

		void protect(SafeAddress address, size_t size)
		{
			if (!address.get() || !size)
			{
				if (!address.get()) SAFEHOOK_THROW("Cannot operate on null address!");
				else if (!size) SAFEHOOK_THROW("Cannot operate on zero size!");
			}

			if (this->address.get() && this->size)
				VirtualProtect((LPVOID)this->address.get(), this->size, old_protect, &old_protect);

			this->address = address;
			this->size = size;
			VirtualProtect((LPVOID)address.get(), size, PAGE_EXECUTE_READWRITE, &old_protect);
		}

		void unprotect()
		{
			if (this->address.get() && this->size)
				VirtualProtect((LPVOID)this->address.get(), this->size, old_protect, &old_protect);

			this->address = uintptr_t(0);
			this->size = 0;
		}

		scoped_unprotect(SafeAddress address, size_t size)
		{
			protect(address, size);
		}

		~scoped_unprotect()
		{
			unprotect();
		}
	};

	class scoped_slim_lock
	{
		PSRWLOCK m_lock;
	public:
		scoped_slim_lock(PSRWLOCK lock) : m_lock(lock)
		{
			if (m_lock)
				AcquireSRWLockExclusive(m_lock);
		}

		~scoped_slim_lock()
		{
			if (m_lock)
				ReleaseSRWLockExclusive(m_lock);
		}
	};

	class scoped_slim_lock_shared
	{
		PSRWLOCK m_lock;
	public:
		scoped_slim_lock_shared(PSRWLOCK lock) : m_lock(lock)
		{
			if (m_lock)
				AcquireSRWLockShared(m_lock);
		}

		~scoped_slim_lock_shared()
		{
			if (m_lock)
				ReleaseSRWLockShared(m_lock);
		}
	};

	inline SRWLOCK g_slimLock = SRWLOCK_INIT;

	// Executes a function while holding a slim lock to ensure thread safety and prevent race conditions.
	template <typename T>
	SAFEHOOK_FORCEINLINE void Sync(T func)
	{
		scoped_slim_lock scopedLock(&g_slimLock);
		func();
	}

	// Fills a memory region with the specified value. If vp is true, it temporarily unprotects the memory region to allow writing.
	SAFEHOOK_FORCEINLINE void MemoryFill(SafeAddress address, unsigned char value, size_t size, bool vp = true)
	{
		if (vp)
		{
			scoped_unprotect unprotect(address.get(), size);

			memset((void*)address.get(), value, size);
		}
		else
		{
			memset((void*)address.get(), value, size);
		}
	}

	// Writes an object of type T to the specified address. If vp is true, it temporarily unprotects the memory region to allow writing.
	template <typename T>
	SAFEHOOK_FORCEINLINE void WriteObject(SafeAddress address, const T& object, bool vp = true)
	{
		if (vp)
		{
			scoped_unprotect unprotect(address.get(), sizeof(T));

			memcpy((void*)address.get(), &object, sizeof(T));
		}
		else
		{
			memcpy((void*)address.get(), &object, sizeof(T));
		}
	}

	// Writes a value of type T to the specified address. If vp is true, it temporarily unprotects the memory region to allow writing.
	template <typename T>
	SAFEHOOK_FORCEINLINE void WriteMemory(SafeAddress address, T value, bool vp = true)
	{
		if (vp)
		{
			scoped_unprotect unprotect(address.get(), sizeof(T));

			*(T*)address.get() = value;
		}
		else
		{
			*(T*)address.get() = value;
		}
	}

	// Writes raw memory to the specified address from the provided data buffer. If vp is true, it temporarily unprotects the memory region to allow writing.
	SAFEHOOK_FORCEINLINE void WriteMemoryRaw(SafeAddress address, const void* data, size_t size, bool vp = true)
	{
		if (vp)
		{
			scoped_unprotect unprotect(address.get(), size);

			memcpy((void*)address.get(), data, size);
		}
		else
		{
			memcpy((void*)address.get(), data, size);
		}
	}

	// Reads a value of type T from the specified address. If vp is true, it temporarily unprotects the memory region to allow reading.
	template <typename T>
	SAFEHOOK_FORCEINLINE T ReadMemory(SafeAddress address, bool vp = true)
	{
		if (vp)
		{
			scoped_unprotect unprotect(address.get(), sizeof(T));

			return *(T*)address.get();
		}
		else
		{
			return *(T*)address.get();
		}
	}

	// Reads raw memory from the specified address into the provided data buffer. If vp is true, it temporarily unprotects the memory region to allow reading.
	SAFEHOOK_FORCEINLINE void ReadMemoryRaw(SafeAddress address, void* data, size_t size, bool vp = true)
	{
		if (vp)
		{
			scoped_unprotect unprotect(address.get(), size);
			memcpy(data, (void*)address.get(), size);
		}
		else
		{
			memcpy(data, (void*)address.get(), size);
		}
	}

	// An RAII utility class that backs up a memory region upon construction and restores it upon destruction. It can be used to temporarily modify memory and ensure it is restored to its original state.
	class scoped_backup
	{
		SafeAddress address;
		size_t size;
		unsigned char* backup;
	public:
		scoped_backup() : address(uintptr_t(0)), size(0), backup(nullptr) {}

		scoped_backup(SafeAddress address, size_t size) : address(address), size(size)
		{
			store(address, size);
		}

		~scoped_backup()
		{
			restore();
			if (backup)
			{
				delete[] backup;
				backup = nullptr;
			}
		}

		void store(SafeAddress address, size_t size)
		{
			if (!address.get() || !size)
			{
				if (!address.get()) SAFEHOOK_THROW("Cannot operate on null address!");
				else if (!size) SAFEHOOK_THROW("Cannot operate on zero size!");
			}

			if (backup)
				delete[] backup;

			this->address = address;
			this->size = size;

			backup = new unsigned char[size];
			ReadMemoryRaw(address, backup, size);
		}

		void restore(bool bCheck = true)
		{
			if (backup)
			{
				if (bCheck)
				{
					if (!address.IsValid())
						return;
				}
				
				WriteMemoryRaw(address, backup, size);
			}
		}

		bool empty() const { return !address.get() || !size || !backup; }

		void clear()
		{
			if (backup)
			{
				delete[] backup;
				backup = nullptr;
			}
			address = uintptr_t(0);
			size = 0;
		}

		friend class Hook;
		friend class MidAsmHook;
	};

	// Get the destination address of a branch instruction (jmp, call, etc.) at the given address.
	inline uintptr_t GetBranchDestination(SafeAddress address)
	{
		hde_s disasm = { 0 };
		HDE_DISASM((uint8_t*)(address.get()), &disasm);
		CHECK_ERROR(disasm);

		if (disasm.flags & F_RELATIVE)
		{
			switch (disasm.flags & (F_IMM8 | F_IMM16 | F_IMM32 | SAFEHOOK_BY_ARCH(0, F_IMM64)))
			{
				case F_IMM8:
					return (uintptr_t)(address.get() + disasm.len + disasm.imm.imm8);
				case F_IMM16:
					return (uintptr_t)(address.get() + disasm.len + disasm.imm.imm16);
				case F_IMM32:
					return (uintptr_t)(address.get() + disasm.len + disasm.imm.imm32);
#if SAFEHOOK_X64
				case F_IMM64:
					return (uintptr_t)(address.get() + disasm.len + disasm.imm.imm64); // thinking about it, how can we have relative with 8 bytes long pointer?
#endif
				default:
					break;
			}
		}
		else
		{
#if SAFEHOOK_X64 // x86 HAS far jumps, I don't think anyone would just go into kernel space and make hooks in there, playing with fire you know
			if (disasm.opcode == 0xFF && disasm.flags & F_MODRM)
			{
				switch (disasm.modrm & 0x38)
				{
					case 0x10: // call
					case 0x20: // jmp
						return *(uintptr_t*)(address.get() + disasm.len + disasm.imm.imm32);
					default:
						break;
				}
			}
			else
#endif
			{
				switch (disasm.flags & (F_IMM8 | F_IMM16 | F_IMM32 | SAFEHOOK_BY_ARCH(0, F_IMM64)))
				{
					case F_IMM8:
						return disasm.imm.imm8;
					case F_IMM16:
						return disasm.imm.imm16;
					case F_IMM32:
						return disasm.imm.imm32;
#if SAFEHOOK_X64
					case F_IMM64:
						return disasm.imm.imm64;
#endif
					default:
						break;
				}
			}
		}

		return 0;
	}

	// Make a relative offset from the source address to the destination address, taking into account the size of the instruction.
	SAFEHOOK_FORCEINLINE uintptr_t MakeRelativeOffset(SafeAddress src, SafeAddress dst, size_t instructionSize)
	{
		return (uintptr_t)(dst.get() - (src.get() + instructionSize));
	}

	// Make a jump in the source address to the destination address. Returns the previous destination of the jump.
	inline uintptr_t MakeJMP(SafeAddress src, SafeAddress dst, bool vp = true)
	{
		uintptr_t prev = GetBranchDestination(src);
		size_t typeSize = GetDistanceTypeSize(src, dst);

		scoped_unprotect x;

		switch (typeSize)
		{
			case sizeof(uint8_t):
			{
				if (vp)
					x.protect(src.get(), 2);

				WriteMemory<uint8_t>(src, 0xEB, false);
				WriteMemory<uint8_t>(src + 1, (uint8_t)MakeRelativeOffset(src, dst, 2), false);
				break;
			}
			case sizeof(uint32_t) :
			{
				if (vp)
					x.protect(src.get(), 5);

				WriteMemory<uint8_t>(src, 0xE9, false);
				WriteMemory<uint32_t>(src + 1, (uint32_t)MakeRelativeOffset(src, dst, 5), false);
				break;
			}
#if SAFEHOOK_X64
			case sizeof(uint64_t) :
			{
				if (vp)
					x.protect(src.get(), 14);

				WriteMemory<uint8_t>(src, 0xFF, false);
				WriteMemory<uint8_t>(src + 1, 0x25, false);
				WriteMemory<uint32_t>(src + 2, 0, false);

				WriteMemory<uint64_t>(src + 6, dst.get(), false);
				break;
			}
#endif
			default:
				// SAFEHOOK_THROW("Invalid distance for JMP instruction!"); // this should never happen since we check the distance type size beforehand // +: Should we really throw an exception here?
				break;
		}

		return prev;
	}

	// Make a call in the source address to the destination address. Returns the previous destination of the call.
	inline uintptr_t MakeCALL(SafeAddress src, SafeAddress dst, bool vp = true)
	{
		uintptr_t prev = GetBranchDestination(src);
		size_t typeSize = GetDistanceTypeSize(src, dst);

		scoped_unprotect x;

		switch (typeSize)
		{
			case sizeof(uint8_t) :
			case sizeof(uint32_t) :
			{
				if (vp)
					x.protect(src.get(), 5);

				WriteMemory<uint8_t>(src, 0xE8, false);
				WriteMemory<uint32_t>(src + 1, (uint32_t)MakeRelativeOffset(src, dst, 5), false);
				break;
			}
#if SAFEHOOK_X64
			case sizeof(uint64_t) :
			{
				if (vp)
					x.protect(src.get(), 14);

				WriteMemory<uint8_t>(src, 0xFF, false);
				WriteMemory<uint8_t>(src + 1, 0x15, false);
				WriteMemory<uint32_t>(src + 2, 0, false); // CALL [RIP+0]

				WriteMemory<uint64_t>(src + 6, dst.get(), false);

				break;
			}
#endif
			default:
				// SAFEHOOK_THROW("Invalid distance for CALL instruction!"); // +: Should we really throw an exception here?
				break;
		}

		return prev;
	}

	// Makes NOPs (no-operation instructions) in the specified memory region. The size parameter specifies how many bytes to fill with NOPs. If vp is true, it temporarily unprotects the memory region to allow writing.
	SAFEHOOK_FORCEINLINE void MakeNOP(SafeAddress address, size_t size, bool vp = true)
	{
		MemoryFill(address, 0x90, size, vp);
	}

	// Makes NOPs (no-operation instructions) in the memory region from src to dst. The size of the region is calculated as dst - src. If vp is true, it temporarily unprotects the memory region to allow writing.
	SAFEHOOK_FORCEINLINE void MakeRangedNOP(SafeAddress src, SafeAddress dst, bool vp = true)
	{
		MakeNOP(src, dst - src, vp);
	}

	// Makes a RET (return) instruction at the specified address. If pop is greater than 0, it will also pop the specified number of bytes from the stack before returning. If vp is true, it temporarily unprotects the memory region to allow writing.
	SAFEHOOK_FORCEINLINE void MakeRET(SafeAddress address, int pop = 0)
	{
		scoped_unprotect unprotect(address.get(), 1 + (pop ? 2 : 0));
		if (pop)
		{
			WriteMemory<uint8_t>(address, 0xC2, false);
			WriteMemory<uint16_t>(address + 1, pop, false);
		}
		else
		{
			WriteMemory<uint8_t>(address, 0xC3, false);
		}
	}

	// whenether there's tricks in assembly that would make hde disassembler fail, we can use this function to safely skip over the instruction and get the next instruction address
	SAFEHOOK_FORCEINLINE size_t HdeCheckOffsetFor(hde_s* disasm)
	{
#if SAFEHOOK_X64
		if (disasm->opcode == 0xFF && disasm->flags & F_MODRM)
		{
			switch (disasm->modrm & 0x38)
			{
			case 0x10: // call
			case 0x20: // jmp
				return disasm->len + sizeof(uint64_t);
			default:
				break;
			}
		}
#endif
		return disasm->len;
	}

	// Returns assumed size of the trampoline, which is the number of bytes needed to copy from the source address to create a trampoline. This function disassembles the instructions at the source address until it has enough bytes to accommodate a jump instruction.
	inline size_t GetTrampolineSize(SafeAddress src)
	{
		// cannot really depend on an non-existent trampoline...

		hde_s disasm = { 0 };
		size_t readOffs = 0;
		size_t size = 0;

		while (readOffs < g_JmpInstructionSize)
		{
			HDE_DISASM((uint8_t*)src.get() + readOffs, &disasm);
			CHECK_ERROR(disasm);

			uint8_t *p = (uint8_t*)src.get() + readOffs;
			if ((*p >= 0x70 && *p <= 0x7F))
			{
				size += 6; // jcc rel8 -> jcc rel32
#if SAFEHOOK_X64
				// hope that the trampoline won't get too far away
#endif
			}
			else if (*p == 0xE9 || *p == 0xE8 || *p == 0xEB) // jmp or call or jmp short
			{
				size += SAFEHOOK_BY_ARCH(5, 14);
			}
#if SAFEHOOK_X64
			else if (*p == 0xFF)
			{
				size_t sz = HdeCheckOffsetFor(&disasm);
				size += sz;
				disasm.len = sz;
			}
#endif
			else
			{
				size += disasm.len;
			}

			readOffs += disasm.len;
		}

		return size;
	}

	inline size_t GetByteCodeLength(uint8_t* src, size_t minLength)
	{
		hde_s disasm = { 0 };
		size_t readOffs = 0;
		size_t size = 0;

		while (size < minLength)
		{
			HDE_DISASM(src + readOffs, &disasm);
			CHECK_ERROR(disasm);

			disasm.len = (uint8_t)HdeCheckOffsetFor(&disasm);

			size += disasm.len;
			readOffs += disasm.len;
		}

		return size;
	}

	// Used to make a trampoline in dst, if the dst is null it will calculate how much bytes is the src
	inline size_t CreateTrampoline(uint8_t* src, uint8_t* dst, size_t* tramp_size = nullptr)
	{
		hde_s disasm = { 0 };
		size_t writeOffs = 0;
		size_t readOffs = 0;

		// scoped_unprotect unprotect((size_t)src, 32); // unprotect the source memory so we can read and write to it safely
		// pretty sure that page is already available for reading, so commenting this out for now
		// we should also not use vp here, trampoline should be already allocated with write permission, just not to cause overhead
		// also, we should be fast here, VirtualProtect has an overhead
		// if you are reading this, use writing without virtual protect, we should be fast, not being a slowpoke

		if (!dst)
		{
			return GetTrampolineSize(src);
		}
		else
		{
			size_t jmpInstruction = 0;
			switch (GetDistanceTypeSize(src, dst))
			{
				case sizeof(uint8_t) :
				{
					jmpInstruction = 2; // 1 byte for opcode + 1 byte for offset
					break;
				}
				case sizeof(uint32_t) :
				{
					jmpInstruction = 5; // 1 byte for opcode + 4 bytes for offset
					break;
				}
#if SAFEHOOK_X64
				case sizeof(uint64_t) :
				{
					jmpInstruction = 14; // 2 bytes for opcode + 4 bytes for offset + 8 bytes for absolute address
					break;
				}
#endif
				default:
					// SAFEHOOK_THROW("Invalid distance for trampoline!"); // just don't
					break;
			}

			while (readOffs < jmpInstruction)
			{
				HDE_DISASM(src + readOffs, &disasm);
				CHECK_ERROR(disasm);

				uint8_t* p = src + readOffs;
				uint8_t* q = dst + writeOffs;

				size_t typeSize = GetDistanceTypeSize(p, dst + writeOffs);
				
				if ((*p >= 0x70 && *p <= 0x7F) || (*p == 0x0F && (*(p + 1) >= 0x80 && *(p + 1) <= 0x8F)))
				{
					uintptr_t branchDest = GetBranchDestination(p);
#if SAFEHOOK_X64
					if (typeSize == sizeof(uint64_t))
						SAFEHOOK_THROW("Jcc does not support 64-bit relative offsets!");
#endif
					WriteMemory<uint8_t>(q, 0x0F, false);
					WriteMemory<uint8_t>(q + 1, *p != 0x0F ? *p + 0x10 : *(p + 1), false);

					WriteMemory<uint32_t>(q + 2, (uint32_t)MakeRelativeOffset(q, branchDest, 6), false);

					writeOffs += 6;
				}
				else if (*p == 0xE9 || *p == 0xE8 || *p == 0xEB) // jmp or call or jmp short
				{
					uintptr_t branchDest = GetBranchDestination(p);

#if SAFEHOOK_X64
					if (typeSize == sizeof(uint64_t))
					{
						WriteMemory<uint8_t>(q, 0xFF, false);
						WriteMemory<uint8_t>(q + 1, *p == 0xE8 ? 0x15 : 0x25, false); // call or jmp
						WriteMemory<uint32_t>(q + 2, 0, false); // RIP relative addressing

						WriteMemory<uint64_t>(q + 6, branchDest, false);

						writeOffs += 14;
					}
					else
					{
						if (*p != 0xEB) // jmp or call
						{
							WriteMemory<uint8_t>(q, *p, false); // copy the jmp/call opcode
							WriteMemory<uint32_t>(q + 1, MakeRelativeOffset(q, branchDest, 5), false);
						}
						else // jmp short
						{
							WriteMemory<uint8_t>(q, 0xE9, false); // convert to jmp long
							WriteMemory<uint32_t>(q + 1, MakeRelativeOffset(q, branchDest, 5), false);
						}

						writeOffs += 5;
					}
#else
					if (*p != 0xEB) // jmp or call
					{
						WriteMemory<uint8_t>(q, *p, false); // copy the jmp/call opcode
						WriteMemory<uint32_t>(q + 1, MakeRelativeOffset(q, branchDest, 5), false);
					}
					else // jmp short
					{
						WriteMemory<uint8_t>(q, 0xE9, false); // convert to jmp long
						WriteMemory<uint32_t>(q + 1, MakeRelativeOffset(q, branchDest, 5), false);
					}

					writeOffs += 5;
#endif
				}
#if SAFEHOOK_X64
				else if (disasm.flags & F_MODRM && (disasm.modrm & 0xC7) == 0x05) // RIP relative addressing
				{
					uint32_t oldDisp = disasm.disp.disp32;
					
					uint64_t absTarget = (uint64_t)(p + disasm.len + oldDisp);
					int64_t newDisp = absTarget - (uint64_t)(q + disasm.len);

					if (newDisp > INT32_MAX || newDisp < INT32_MIN)
						SAFEHOOK_REPORT_HERE("Displacement is too far for RIP relative addressing! %p -> %p", p, q);

					uint8_t immSize = 0;
					memcpy(dst + writeOffs, src + readOffs, disasm.len);
					switch (disasm.flags & (F_IMM8 | F_IMM16 | F_IMM32 | F_IMM64))
					{
						case F_IMM8: immSize = 1; break;
						case F_IMM16: immSize = 2; break;
						case F_IMM32: immSize = 4; break;
						case F_IMM64: immSize = 8; break;
						default:
							break;
					}

					uint32_t dispOffset = disasm.len - immSize - 4;

					*(int32_t*)(q + dispOffset) = (int32_t)newDisp;

					writeOffs += disasm.len;
				}
#endif
				else
				{
					memcpy(dst + writeOffs, src + readOffs, disasm.len);
					writeOffs += disasm.len;
				}
				readOffs += disasm.len;
			}
		}

		MakeJMP(dst + writeOffs, src + readOffs, false); // jmp back to the original routine after the overwritten bytes

		if (tramp_size)
			*tramp_size = writeOffs;

		return readOffs;
	}

	class cTrackHook
	{
	protected:
		void *m_hook;
		cTrackHook *m_next;
	public:
		cTrackHook(void *hook, cTrackHook *next) : m_hook(hook), m_next(next) {}

		virtual ~cTrackHook() {}

		friend void CleanupHooks();
	};

	class cTrackHookHook : public cTrackHook
	{
	public:
		cTrackHookHook(class Hook* hook, cTrackHook* next) : cTrackHook(hook, next) {}

		virtual ~cTrackHookHook()
		{
			if (m_hook)
			{
				class Hook* hook = (class Hook*)m_hook;
				((void(__thiscall*)(class Hook*))**(void***)hook)(hook);
			}
		}
	};

	class cTrackHookMidAsmHook : public cTrackHook
	{
	public:
		cTrackHookMidAsmHook(class MidAsmHook* hook, cTrackHook* next) : cTrackHook(hook, next) {}

		virtual ~cTrackHookMidAsmHook()
		{
			if (m_hook)
			{
				class MidAsmHook* hook = (class MidAsmHook*)m_hook;
				((void(__thiscall*)(class MidAsmHook*))**(void***)hook)(hook);
			}
		}
	};

	inline cTrackHook* g_trackHooks = nullptr;

	// This would cleanup every hook that was created, thus forceful shutting down is easier
	inline void CleanupHooks()
	{
		scoped_slim_lock scopedLock(&g_slimLock);
		while (g_trackHooks)
		{
			cTrackHook* pNext = g_trackHooks->m_next;
			delete g_trackHooks;
			g_trackHooks = pNext;
		}
	}

	class Hook
	{
		uint8_t* m_target;
		uint8_t* m_hook;
		size_t m_trampolineSize;

		struct
		{
			union
			{
				struct
				{
					uint32_t bEnabled : 1;
					uint32_t bTrampolineCreated : 1;
					uint32_t bTrampolineLinked : 1;
				};
				uint32_t i32;
			};
		} m_state;
		uint8_t* m_trampoline;
		scoped_backup m_originalBytes;

		void CreateTrampoline()
		{
			if (!m_state.bTrampolineCreated)
			{
				size_t trampolineSize = GetTrampolineSize(m_target);
				// scary thing here is that original function code might be 3-4 bytes long, and knowing how sections are operated, we might end up spoiling the next function's code if we are working with no alignment code
				m_originalBytes.store(m_target, GetByteCodeLength(m_target, 5)); // try relative first

				void* pPage = SAFEHOOK_BY_ARCH(g_pageController.alloc(trampolineSize + 14), g_pageController.allocNear(m_target, trampolineSize + 14)); // 14 to be certain for x64 and x86
#if SAFEHOOK_X64
				if (!pPage) // allocating near failed, and now we will just try far jmp indirect, FUCK!
				{
					m_originalBytes.clear();
					m_originalBytes.store(m_target, GetByteCodeLength(m_target, 14)); // yay, 14 bytes

					pPage = g_pageController.alloc(trampolineSize + 14);
				}
#endif

				if (pPage)
				{
					m_trampoline = (unsigned char*)pPage;
					SafeHook::CreateTrampoline(m_target, m_trampoline, &m_trampolineSize);

					m_state.bTrampolineCreated = true;
				}
				else
				{
					SAFEHOOK_THROW("Failed to allocate memory for trampoline!");
				}
			}
		}
	public:
		Hook()
		{
			m_target = m_hook = m_trampoline = nullptr;
			m_trampolineSize = m_state.i32 = 0;
		}

		Hook(void* pTarget, void* pHook, bool bEnable = true, void** pOriginal = nullptr)
		{
			try
			{
				if (!pTarget || !pHook)
					SAFEHOOK_THROW("Target and hook addresses cannot be null!");

				m_target = (unsigned char*)pTarget;
				m_hook = (unsigned char*)pHook;
				CreateTrampoline();

				if (pOriginal)
					*pOriginal = m_trampoline;

				if (bEnable)
					Enable();

				g_trackHooks = new cTrackHookHook(this, g_trackHooks);
			}
			SAFEHOOK_CATCH(e);
		}

		Hook(void* pTarget, void* pHook, void** pOriginal)
		{
			try
			{
				if (!pTarget || !pHook)
					SAFEHOOK_THROW("Target and hook addresses cannot be null!");

				m_target = (unsigned char*)pTarget;
				m_hook = (unsigned char*)pHook;
				CreateTrampoline();
				if (pOriginal)
					*pOriginal = m_trampoline;

				Enable();

				g_trackHooks = new cTrackHookHook(this, g_trackHooks);
			}
			SAFEHOOK_CATCH(e);
		}

		bool valid() const { return CheckValidAddress(m_target) && m_hook && m_state.bTrampolineCreated; }
		bool enabled() const { return m_state.bEnabled; } // in case you want to use bool toggle storage for this without declaring a new variable

		void Enable()
		{
			m_state.bEnabled = true;
			if (m_state.bTrampolineCreated && !m_state.bTrampolineLinked)
			{
				Sync([&]()
				{
					Vector<DWORD> threadIds;
					EnumerateThreads(threadIds);
					
					SuspendThreads(threadIds);
					scoped_unprotect unprotect(m_target, m_originalBytes.size);

					MakeJMP(m_target, m_hook, false);
					FlushInstructionCache(GetCurrentProcess(), m_target, m_originalBytes.size);

					RedirectThreads(threadIds, m_target, m_originalBytes.size, m_trampoline);

					ResumeThreads(threadIds);
				});

				m_state.bTrampolineLinked = true;
			}
		}

		void Disable()
		{
			m_state.bEnabled = false;
			if (m_state.bTrampolineCreated && m_state.bTrampolineLinked)
			{
				Sync([&]()
				{
					Vector<DWORD> threadIds;
					EnumerateThreads(threadIds);

					SuspendThreads(threadIds);

					m_originalBytes.restore(false); // Must ensure that address is valid
					FlushInstructionCache(GetCurrentProcess(), m_target, m_originalBytes.size);

					RedirectThreads(threadIds, m_trampoline, m_trampolineSize, m_target);

					ResumeThreads(threadIds);
				});

				m_state.bTrampolineLinked = false;
			}
		}

		void SafeEnable()
		{
			if (!valid())
				SAFEHOOK_REPORT_HERE("Hook is not valid!");

			Enable();
		}

		void SafeDisable()
		{
			if (!valid())
				SAFEHOOK_REPORT_HERE("Hook is not valid!");

			Disable();
		}

		~Hook()
		{
			if (valid())
				Disable();

			g_pageController.release(m_trampoline);

			m_trampoline = nullptr;
			m_target = m_hook = nullptr;
			m_trampolineSize = 0;
			m_state.i32 = 0;
		}

		virtual void OnDestruct() 
		{
			this->~Hook();
		}
	};

#if SAFEHOOK_X64
	union REG
	{
		unsigned __int64 i64;
		unsigned int i32;
		unsigned short i16;
		unsigned char i8;

		float f32;
		double f64;

		unsigned char* pi8;
		unsigned short* pi16;
		unsigned int* pi32;
		unsigned __int64* pi64;

		float* pf32;
		double* pf64;

		// methods used for moving value with zero extension
		SAFEHOOK_FORCEINLINE void Set(unsigned char i8) { i64 = 0LL;  this->i8 = i8; }
		SAFEHOOK_FORCEINLINE void Set(unsigned short i16) { i64 = 0LL; this->i16 = i16; }
		SAFEHOOK_FORCEINLINE void Set(unsigned int i32) { i64 = 0LL; this->i32 = i32; }
		SAFEHOOK_FORCEINLINE void Set(unsigned __int64 i64) { this->i64 = i64; }
		SAFEHOOK_FORCEINLINE void Set(float f32) { i64 = 0LL; this->f32 = f32; }
		SAFEHOOK_FORCEINLINE void Set(double f64) { this->f64 = f64; } // we don't have to clear out i64, already replaced by f64
	};
#else
	union REG
	{
		unsigned int i32;
		unsigned short i16;
		unsigned char i8;

		float f32;

		unsigned char* pi8;
		unsigned short* pi16;
		unsigned int* pi32;

		float* pf32;

		// methods used for moving value with zero extension
		SAFEHOOK_FORCEINLINE void Set(unsigned char i8) { i32 = 0; this->i8 = i8; } 
		SAFEHOOK_FORCEINLINE void Set(unsigned short i16) { i32 = 0; this->i16 = i16; }
		SAFEHOOK_FORCEINLINE void Set(unsigned int i32) { this->i32 = i32; }
		SAFEHOOK_FORCEINLINE void Set(float f32) { this->f32 = f32; }
	};
#endif

	union FLAGS
	{
		unsigned short i16;
		struct
		{
			unsigned short CF : 1; // Carry Flag
			unsigned short BRKI : 1; // I/O Trap, always 1 on all other x86 processors
			unsigned short PF : 1; // Parity Flag
			unsigned short Reserved1 : 1;
			unsigned short AF : 1; // Auxiliary Carry Flag
			unsigned short Reserved2 : 1;
			unsigned short ZF : 1; // Zero Flag
			unsigned short SF : 1; // Sign Flag

			unsigned short TF : 1; // Trap Flag
			unsigned short IF : 1; // Interrupt Enable Flag
			unsigned short DF : 1; // Direction Flag
			unsigned short OF : 1; // Overflow Flag
			unsigned short IOPL : 2; // I/O Privilege Level
			unsigned short NT : 1; // Nested Task Flag
			unsigned short MD : 1; // Mode Flag
		};
	};

	union EFLAGS
	{
		unsigned int i32;
		struct
		{
			unsigned int CF : 1; // Carry Flag
			unsigned int BRKI : 1; // I/O Trap, always 1 on all other x86 processors
			unsigned int PF : 1; // Parity Flag
			unsigned int Reserved1 : 1;
			unsigned int AF : 1; // Auxiliary Carry Flag
			unsigned int Reserved2 : 1;
			unsigned int ZF : 1; // Zero Flag
			unsigned int SF : 1; // Sign Flag

			unsigned int TF : 1; // Trap Flag
			unsigned int IF : 1; // Interrupt Enable Flag
			unsigned int DF : 1; // Direction Flag
			unsigned int OF : 1; // Overflow Flag
			unsigned int IOPL : 2; // I/O Privilege Level
			unsigned int NT : 1; // Nested Task Flag
			unsigned int MD : 1; // Mode Flag

			unsigned int RF : 1; // Resume Flag
			unsigned int VM : 1; // Virtual 8086 Mode
			unsigned int AC : 1; // Alignment Check
			unsigned int VIF : 1; // Virtual Interrupt Flag
			unsigned int VIP : 1; // Virtual Interrupt Pending
			unsigned int ID : 1; // Can use CPUID instruction
			unsigned int Reserved : 8; 

			unsigned int AESSCH : 1; // AES Key schedule loaded flag
			unsigned int AI : 1; // Alternative Instruction Set
		};
	};

#if SAFEHOOK_X64
	union RFLAGS
	{
		unsigned long long i64;
		struct
		{
			unsigned long long CF : 1; // Carry Flag
			unsigned long long BRKI : 1; // I/O Trap, always 1 on all other x86 processors
			unsigned long long PF : 1; // Parity Flag
			unsigned long long Reserved1 : 1;
			unsigned long long AF : 1; // Auxiliary Carry Flag
			unsigned long long Reserved2 : 1;
			unsigned long long ZF : 1; // Zero Flag
			unsigned long long SF : 1; // Sign Flag

			unsigned long long TF : 1; // Trap Flag
			unsigned long long IF : 1; // Interrupt Enable Flag
			unsigned long long DF : 1; // Direction Flag
			unsigned long long OF : 1; // Overflow Flag
			unsigned long long IOPL : 2; // I/O Privilege Level
			unsigned long long NT : 1; // Nested Task Flag
			unsigned long long MD : 1; // Mode Flag

			unsigned long long RF : 1; // Resume Flag
			unsigned long long VM : 1; // Virtual 8086 Mode
			unsigned long long AC : 1; // Alignment Check
			unsigned long long VIF : 1; // Virtual Interrupt Flag
			unsigned long long VIP : 1; // Virtual Interrupt Pending
			unsigned long long ID : 1; // Can use CPUID instruction
			unsigned long long Reserved : 8; 

			unsigned long long AESSCH : 1; // AES Key schedule loaded flag
			unsigned long long AI : 1; // Alternative Instruction Set
			
			unsigned long long Reserved32 : 32; // Reserved bits for 64-bit mode
		};
	};
#endif

	typedef struct FPUREG
	{
	private: // we shouldn't be really exposed to "internals" so let's just hide it and provide a way to convert to/from double, which is what most people would want to use
		unsigned long long Mantissa;
		unsigned short ExponentSign;
		char Reserved[6];
	private:
		double toDouble() const
		{
			unsigned short exp = ExponentSign & 0x7FFF;
			int sign = ExponentSign & 0x8000 ? -1 : 1;
			unsigned long long mantissa = Mantissa;

			if (exp == 0 && mantissa == 0)
				return 0.0 * sign;

			int realExp = exp - 16383; // 16383 is the bias for 80-bit extended precision

			double fraction = (double)mantissa / (double)(1ULL << 63); // The mantissa is effectively a fixed-point number with an implicit leading 1, so we divide by 2^63 to get the fractional part

			return sign * ldexp(fraction, realExp); // ldexp is used to compute fraction * 2^realExp efficiently and accurately
		}

#if !defined(_MSC_VER)
		// more precision
		long double toLongDouble() const
		{
			unsigned short exp = ExponentSign & 0x7FFF;
			int sign = ExponentSign & 0x8000 ? -1 : 1;
			unsigned long long mantissa = Mantissa;

			if (exp == 0 && mantissa == 0)
				return 0.0L * sign;

			int realExp = exp - 16383;

			long double fraction = (long double)mantissa / (long double)(1ULL << 63); 

			return sign * ldexpl(fraction, realExp);
		}

#endif
		void setDouble(double x)
		{
			memset(this, 0, sizeof(FPUREG));

			if (x == 0.0)
			{
				if (signbit(x))
					ExponentSign = 0x8000;

				return;
			}

			int exp;

			double frac = frexp(abs(x), &exp); // breaks x into its binary significand (frac) and an integral exponent for 2 (exp), such that x = frac * 2^exp

			frac *= 2.0;
			exp -= 1;

			uint16_t sign = signbit(x) ? 0x8000 : 0;
			uint16_t biasedExp = (uint16_t)(exp + 16383); // add the bias for 80-bit extended precision
			ExponentSign = sign | biasedExp;

			Mantissa = (unsigned long long)(frac * (double)(1ULL << 63)); // convert the fractional part to the fixed-point representation used in the mantissa
		}
		
		// Microsoft are jerks for not supporting long double and instead treat it as simple double
#if !defined(_MSC_VER)
		// more precision
		void setLongDouble(long double x)
		{
			memset(this, 0, sizeof(FPUREG));

			if (x == 0.0L)
			{
				if (signbit(x))
					ExponentSign = 0x8000;

				return;
			}

			int exp;

			long double frac = frexpl(abs(x), &exp);

			frac *= 2.0L;
			exp -= 1;

			uint16_t sign = signbit(x) ? 0x8000 : 0;
			uint16_t biasedExp = (uint16_t)(exp + 16383);
			ExponentSign = sign | biasedExp;

			Mantissa = (unsigned long long)(frac * (long double)(1ULL << 63));
		}
#endif
	public:
#if defined(_MSC_VER) // prefer long double for non-MSVC compilers, since MSVC doesn't support it properly
		operator double() const { return toDouble(); }
#else
		operator long double() const { return toLongDouble(); }
#endif
		// operator float() const { return (float)toDouble(); } // use double instead, compiler gets confused which one to use

		FPUREG() : Mantissa(0), ExponentSign(0) {}
#if defined(_MSC_VER)
		FPUREG(double x) { setDouble(x); }
#else
		FPUREG(long double x) { setLongDouble(x); }
#endif

#if defined(_MSC_VER)
		FPUREG& operator=(double x) { setDouble(x); return *this; }
		FPUREG& operator*=(double x) { setDouble(toDouble() * x); return *this; }
		FPUREG& operator/=(double x) { setDouble(toDouble() / x); return *this; }
		FPUREG& operator+=(double x) { setDouble(toDouble() + x); return *this; }
		FPUREG& operator-=(double x) { setDouble(toDouble() - x); return *this; }

		FPUREG operator*(double x) const { FPUREG result; result.setDouble(toDouble() * x); return result; }
		FPUREG operator/(double x) const { FPUREG result; result.setDouble(toDouble() / x); return result; }
		FPUREG operator+(double x) const { FPUREG result; result.setDouble(toDouble() + x); return result; }
		FPUREG operator-(double x) const { FPUREG result; result.setDouble(toDouble() - x); return result; }
#else
		FPUREG& operator=(long double x) { setLongDouble(x); return *this; }
		FPUREG& operator*=(long double x) { setLongDouble(toLongDouble() * x); return *this; }
		FPUREG& operator/=(long double x) { setLongDouble(toLongDouble() / x); return *this; }
		FPUREG& operator+=(long double x) { setLongDouble(toLongDouble() + x); return *this; }
		FPUREG& operator-=(long double x) { setLongDouble(toLongDouble() - x); return *this; }

		FPUREG& operator*(long double x) const { FPUREG result; result.setLongDouble(toLongDouble() * x); return result; }
		FPUREG& operator/(long double x) const { FPUREG result; result.setLongDouble(toLongDouble() / x); return result; }
		FPUREG& operator+(long double x) const { FPUREG result; result.setLongDouble(toLongDouble() + x); return result; }
		FPUREG& operator-(long double x) const { FPUREG result; result.setLongDouble(toLongDouble() - x); return result; }
#endif
	} FPUREG;

	typedef union
	{
		unsigned __int64 i64[2];
		unsigned int i32[4];
		unsigned short i16[8];
		unsigned char i8[16];

		float f32[4];
		double f64[2];
	} XMMREG;

	struct FPUx87SSE
	{
		struct FPUUnit
		{
			unsigned short FCW;
			unsigned short FSW;
			unsigned char FTW;
			unsigned char Reserved1;
			unsigned short FOP;
#if SAFEHOOK_X86
			unsigned int FIP;
			unsigned int FCS;
			unsigned int FDP;
			unsigned int FDS;
#elif SAFEHOOK_X64
			unsigned long long FIP;
			unsigned long long FDP;
#endif
			unsigned int MXCSR;
			unsigned int MXCSR_MASK;

			FPUREG st[8];

			int GetTop() const { return (FSW >> 11) & 0x7; }
		} FPU;

		XMMREG xmm[16];

		static_assert(sizeof(FPUUnit) == 0xA0, "FPUUnit size mismatch!");

		char _padding[512 - 0xA0 - 16 * 16];
	};

	static_assert(sizeof(FPUx87SSE) == 512, "FPUx87SSE size mismatch!");

#if SAFEHOOK_X86
	typedef struct CTX
	{
		FPUx87SSE FPUandSSE;

		REG ebx;
		REG ecx;
		REG edx;
		REG esi;
		REG edi;
		REG saved_esp;
		REG ebp;

		REG& eax() { return *(REG*)(saved_esp.i32); }
		EFLAGS& eflags() { return *(EFLAGS*)(saved_esp.i32 + 4); }
		const REG esp() const { return (REG)(saved_esp.i32 + 0xC); } // you are not allowed to modify stack pointer

		XMMREG& xmm(int i _In_range_(0, 7)) { return FPUandSSE.xmm[i]; }
		FPUREG& st(int i _In_range_(-1, 7)) 
		{
			if (i == -1)
				return FPUandSSE.FPU.st[FPUandSSE.FPU.GetTop()];
			else
				return FPUandSSE.FPU.st[i];
		}
	} CTX;
#else
	typedef struct CTX
	{
		FPUx87SSE FPUandSSE;

		REG rbx;
		REG rcx;
		REG rdx;
		REG rsi;
		REG rdi;
		REG saved_rsp;
		REG rbp;
		REG r8;
		REG r9;
		REG r10;
		REG r11;
		REG r12;
		REG r13;
		REG r14;
		REG r15;

		REG& rax() { return *(REG*)(saved_rsp.i64); }
		RFLAGS& rflags() { return *(RFLAGS*)(saved_rsp.i64 + 8); }
		const REG rsp() const { return (REG)(saved_rsp.i64 + 0x18); } // you are not allowed to modify stack pointer

		XMMREG& xmm(int i _In_range_(0, 15)) { return FPUandSSE.xmm[i]; }
		FPUREG& st(int i _In_range_(-1, 7)) 
		{
			if (i == -1)
				return FPUandSSE.FPU.st[FPUandSSE.FPU.GetTop()];
			else
				return FPUandSSE.FPU.st[i];
		}
	};
#endif
	// @brief Can be used in cave or in mid-function hooking
	// @brief If you can place it in instead of the opcode with 5 bytes length you won't need to use MidAsmHook(which uses trampoline for safety)
	class MidAsmHookUnsafe
	{
	private:
		scoped_backup original_cave_bytes;
		SafeAddress cave_address;
		unsigned char *hook_bytes = nullptr;
	public:
		MidAsmHookUnsafe() = default;

		MidAsmHookUnsafe(SafeAddress address_of_cave, void(__cdecl* hook_func)(CTX&))
		{
			cave_address = address_of_cave;
			hook_bytes = (unsigned char*)g_pageController.alloc(sizeof(asm_data) + g_JmpInstructionSize); // allocate memory for the hook code and the jump back to the original function
			if (!hook_bytes)
				SAFEHOOK_THROW("Failed to allocate memory for hook bytes!");

			memcpy(hook_bytes, asm_data, sizeof(asm_data));
			MakeJMP(hook_bytes + sizeof(asm_data), hook_func, false);

			MakeCALL(cave_address, hook_bytes);
		}

		~MidAsmHookUnsafe()
		{
			if (!hook_bytes) // if hook_bytes is nullptr, it might mean two things, wrapper does not want to restore the original bytes, or was not allocated at all
				original_cave_bytes.clear();

			if (hook_bytes)
			{
				g_pageController.release(hook_bytes);
				hook_bytes = nullptr;
			}

			cave_address = uintptr_t(0);
		}

		friend class MidAsmHook;
	};

	// @brief Safer version, but actually a simple wrapper
	class MidAsmHook
	{
	private:
		MidAsmHookUnsafe unsafe_hook;
		unsigned char* trampoline = nullptr;
		scoped_backup original_bytes;

		// Try to find a place to inject the trampoline
		// You cannot just put a trampoline in the middle of instruction and expect it to work
		SAFEHOOK_BY_ARCH(
		void handleTrampoline(uintptr_t _address, size_t& orig_size),
		void handleTrampoline(uintptr_t _address, size_t& orig_size, bool bTryAllocNear = true))
		{
			size_t orignal_size = GetTrampolineSize(_address);

#if SAFEHOOK_X64
			if (bTryAllocNear)
			{
				trampoline = (unsigned char*)g_pageController.allocNear((void*)_address, orignal_size + g_JmpInstructionSize * 2);
				if (!trampoline)
					trampoline = (unsigned char*)g_pageController.alloc(orignal_size + g_JmpInstructionSize * 2);
			}
			else
#endif
			{
				trampoline = (unsigned char*)g_pageController.alloc(orignal_size + g_JmpInstructionSize * 2);
			}
			if (!this->trampoline)
			{
				SAFEHOOK_THROW_FORMAT("Failed to allocate memory for %p!", (void*)_address);
			}
			size_t typeSize = GetDistanceTypeSize(trampoline, _address + orignal_size);
			size_t jmpSize = 0;
			switch (typeSize)
			{
			case 1:
				jmpSize = 2;
				break;
			case 4:
				jmpSize = 5;
				break;
#if SAFEHOOK_X64
			case 8:
				jmpSize = 14;
				break;
#endif
			default:
				break;
			}

			MakeNOP(trampoline, jmpSize, false);

			orig_size = CreateTrampoline((unsigned char*)_address, this->trampoline + jmpSize, nullptr);
		}
	public:
		MidAsmHook() = default;

		MidAsmHook(SafeAddress _address, void(__cdecl* hook_func)(CTX&))
		{
			size_t orig_size = 0;
			try
			{
				handleTrampoline(_address.get(), orig_size);
			}
			SAFEHOOK_CATCH_RET(e);

			if (!trampoline)
				return;

			try
			{
				new (&unsafe_hook) MidAsmHookUnsafe(trampoline, hook_func);
			}
			SAFEHOOK_CATCH_RET(e);
			// we need to proceed with the "MidAsmHookUnsafe" before it is connected to the main routine, if we do it after, we might run into unhandled exception

			Sync([&]()
			{
				Vector<DWORD> threadIds;
				EnumerateThreads(threadIds);

				SuspendThreads(threadIds);

				{
					scoped_unprotect unprotect(_address.get(), orig_size);
					original_bytes.store(_address.get(), orig_size);

					memset((void*)_address.get(), 0x90, orig_size);
				}

				MakeJMP(_address, trampoline);

				RedirectThreads(threadIds, _address.get(), orig_size, trampoline);
				FlushInstructionCache(GetCurrentProcess(), (void*)_address.get(), orig_size);

				ResumeThreads(threadIds);
			});

			g_trackHooks = new cTrackHookMidAsmHook(this, g_trackHooks);

			// basically
			// call hook_wrapper
			// [original instructions]
			// jmp original_func + original_instructions_size
		}

		~MidAsmHook()
		{
			Sync([&]()
			{
				Vector<DWORD> threadIds;
				EnumerateThreads(threadIds);

				SuspendThreads(threadIds);

				if (unsafe_hook.hook_bytes)
				{
					original_bytes.restore(true);
					FlushInstructionCache(GetCurrentProcess(), (void*)unsafe_hook.cave_address.get(), original_bytes.size);
				}

				RedirectThreads(threadIds, unsafe_hook.cave_address.get(), original_bytes.size, original_bytes.address);

				ResumeThreads(threadIds);
			});

			g_pageController.release(unsafe_hook.hook_bytes);
			unsafe_hook.hook_bytes = nullptr; // Do not restore bytes for a wrapper

			if (trampoline)
			{
				g_pageController.release(trampoline);
				trampoline = nullptr; // everything else is handled by page controller
			}

			// unsafe_hook will automatically destruct itself
		}

		virtual void OnDestruct()
		{
			this->~MidAsmHook();
		}
	};

#if SAFEHOOK_TEST
	inline void TestPageController()
	{
		void* p = g_pageController.alloc(PageController::PAGE_SIZE);
		void* p2 = g_pageController.alloc(PageController::PAGE_SIZE); // generally two pages

		g_pageController.release(p); // check if the page controller can handle releasing pages correctly, tested only.. via debugging? Is this even a test? Maybe...
		g_pageController.release(p2);
	}
#endif

#undef CHECK_ERROR
}