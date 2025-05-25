/*!
 * @file relib.hpp
 * @author undisassemble
 * @brief ReLib main include
 * @version 0.0.0
 * @date 2025-05-25
 * @copyright MIT License
 */

#pragma once

// Standard headers
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

// Stuff
typedef uint64_t QWORD;
#define __RELIB_VERSION__ "0.0.0-dev" // Remove dev tag for releases
#ifdef RELIB_SHARED
#ifdef _RELIB_INTERNAL
#define RELIB_EXPORT __declspec(dllexport)
#else
#define RELIB_EXPORT __declspec(dllimport)
#endif
#else
#define RELIB_EXPORT
#endif

// Its 1 in the morning, I've ha d to fully recompile the entirety of YAP 6 times to try and get cmake t ocut out the ufll path for this shit to work, so fuck you, you're not getting file information. line and debugger info shojdl e pleyny. im going to sleep. also fuck gcc fo including the ull path and not just the file name.
#define __RELIB_ASSERT(expr, line) if (!(expr)) { _ReLibData.ErrorCallback("Assertion (" #expr ") failed at line " #line "\n"); DebugBreak(); exit(1); }
#define _RELIB_ASSERT(expr, line) __RELIB_ASSERT(expr, line)

/*!
 * @brief Ensures expression `expr` is true, exits if it's not.
 * 
 * @param [in] expr Expression to check.
 */
#define RELIB_ASSERT(expr) _RELIB_ASSERT(expr, __LINE__)

/*!
 * @brief Data about what relib is doing
 * @todo Ensure this is threadsafe
 */
typedef struct _ReLibMetrics_t {
	struct {
		uint64_t InUse = 0;    //!< Total memory in use
		uint64_t Reserved = 0; //!< Total memory reserved.
	} Memory;
} ReLibMetrics_t;

// Internal data
RELIB_EXPORT void _BaseLogger(const char* message, ...);
typedef struct __ReLibData_t {
	void (__stdcall *ErrorCallback)(const char* message, ...) = _BaseLogger;
	void (__stdcall *WarningCallback)(const char* message, ...) = _BaseLogger;
	void (__stdcall *LoggingCallback)(const char* message, ...) = _BaseLogger;
} _ReLibData_t;
RELIB_EXPORT extern _ReLibData_t _ReLibData;

// Exports
namespace relib {
	/*!
	 * @brief Set callback for error reporting.
	 * 
	 * @param callback Function called on errors.
	 */
	RELIB_EXPORT void SetErrorCallback(void (__stdcall *callback)(const char* message, ...));

	/*!
	 * @brief Set callback for warning reporting.
	 * 
	 * @param callback Function called on warnings.
	 */
	RELIB_EXPORT void SetWarningCallback(void (__stdcall *callback)(const char* message, ...));

	/*!
	 * @brief Set callback for general logging information.
	 * 
	 * @param callback Function called for logging.
	 */
	RELIB_EXPORT void SetLoggingCallback(void (__stdcall *callback)(const char* message, ...));
};

RELIB_EXPORT extern ReLibMetrics_t ReLibMetrics;

/*!
 * @brief Buffer for raw data.
 * @todo Add a flag that disables `Release()`
 */
class Buffer {
private:
	BYTE* pBytes = NULL;                 //!< Pointer to raw data.
	size_t szBytes = 0;                  //!< Size of `pBytes`.

public:
	inline Buffer() { pBytes = NULL; szBytes = 0; }

	/*!
	 * @brief Merge with another buffer.
	 * 
	 * @param [in] Other Other buffer to merge with.
	 * @param [in] bFreeOther Release other buffers memory.
	 */
	RELIB_EXPORT void Merge(_In_ Buffer Other, _In_ bool bFreeOther = true);

	/*!
	 * @brief Allocate `Size` bytes.
	 * @remark This is not cumulative, if you have 5 bytes reserved and allocate 3 you get 3, not 8.
	 * 
	 * @param [in] Size Number of bytes to allocate.
	 */
	RELIB_EXPORT void Allocate(_In_ size_t Size);

	/*!
	 * @brief Release memory used by buffer.
	 */
	RELIB_EXPORT void Release();

	/*!
	 * @brief Get the Data object.
	 * 
	 * @return Pointer to data.
	 */
	inline BYTE* Data() const {
		return pBytes;
	}

	/*!
	 * @brief Get the Size object.
	 * 
	 * @return Size of data.
	 */
	inline size_t Size() const {
		return szBytes;
	}
};

/*!
 * @brief List it items.
 * 
 * @tparam T Type of data stored.
 */
template <typename T>
class Vector : public Buffer {
protected:
	DWORD nItems = 0;                    //!< Number of items (of type T) stored.

public:
	bool bExponentialGrowth : 1 = false; //!< Whether extra memory should be reserved when limit reached, faster on larger vectors.

	/*!
	 * @brief Reserves additional memory.
	 * @remark Unlike `Buffer::Allocate(_In_ size_t Size)`, this is cumulative and adds additional memory.
	 * 
	 * @param [in] nItems Number of items to reserve
	 */
	inline void Reserve(_In_ size_t nItems) {
		Allocate(Buffer::Size() + nItems * sizeof(T));
	}

	/*!
	 * @brief Merge with another vector.
	 * 
	 * @param [in] Other Other vector to merge with.
	 * @param [in] bFreeOther Don't free the other vector.
	 */
	void Merge(_In_ Vector<T> Other, _In_ bool bFreeOther = false) {
		Reserve(Other.Size());
		RELIB_ASSERT(Buffer::Size() > nItems * sizeof(T));
		RELIB_ASSERT(!memcpy_s(Buffer::Data() + nItems * sizeof(T), Buffer::Size() - nItems * sizeof(T), Other.Data(), Other.Size() * sizeof(T)));
		nItems += Other.Size();
		ReLibMetrics.Memory.InUse += Other.nItems * sizeof(T);
		if (bFreeOther) Other.Release();
	}

	/*!
	 * @brief Number of items in the vector.
	 * @todo Rename to `Count()`.
	 * 
	 * @return Number of items.
	 */
	inline size_t Size() const {
		return nItems;
	}

	/*!
	 * @brief Total number of items that can fit before more memory will be reserved.
	 * 
	 * @return Number of items.
	 */
	inline size_t Capacity() const {
		return Buffer::Size() / sizeof(T);
	}

	/*!
	 * @brief Reserve memory based on number of items.
	 */
	void Grow() {
		// Create buffer
		if (Buffer::Size() < sizeof(T) || !Buffer::Data()) {
			Allocate(sizeof(T) * (bExponentialGrowth ? 10 : 1));
		}
		
		// Expand buffer
		else if (Buffer::Size() < nItems * sizeof(T)) {
			uint64_t NewSize = Buffer::Size();
			if (bExponentialGrowth) {
				while (NewSize < nItems * sizeof(T)) {
					NewSize = sizeof(T) * (NewSize / sizeof(T)) * 1.1;
				}
			} else {
				NewSize = nItems * sizeof(T);
			}
			Allocate(NewSize);
		}
	}

	/*!
	 * @brief Get item at index i.
	 * 
	 * @param [in] i Index.
	 * @return Item.
	 */
	T& At(_In_ DWORD i) {
		// Yeah idk what the fuck I was talking about when I wrote that comment, dont check git history please, thanks.
		RELIB_ASSERT(i < nItems);
		return ((T*)Data())[i];
	}

	/*!
	 * @brief Get/set item at index i.
	 * 
	 * @param [in] i Index.
	 * @return Item.
	 */
	T& operator[](_In_ int i) {
		RELIB_ASSERT(i < nItems);
		return ((T*)Data())[i];
	}

	/*!
	 * @brief Get item at index i.
	 * 
	 * @param [in] i Index.
	 * @return Item.
	 */
	const T& operator[](_In_ int i) const {
		RELIB_ASSERT(i < nItems);
		return ((T*)Data())[i];
	}

	/*!
	 * @brief Push item to end of vector.
	 * 
	 * @param [in] Item Item to push.
	 */
	void Push(_In_ T Item) {
		nItems++;
		Grow();
		operator[](nItems - 1) = Item;
		ReLibMetrics.Memory.InUse += sizeof(T);
	}

	/*!
	 * @brief Pop item from end vector.
	 * 
	 * @return Popped item.
	 */
	T Pop() {
		if (!Buffer::Size() || !Buffer::Data()) {
			T ret;
			ZeroMemory(&ret, sizeof(T));
			return ret;
		}
		T ret = At(Size() - 1);
		ReLibMetrics.Memory.InUse -= sizeof(T);
		if (Size() == 1) {
			Release();
		} else {
			nItems--;
		}
		return ret;
	}

	/*!
	 * @brief Replace single element with vector.
	 * 
	 * @param [in] i Index to replace.
	 * @param [in] Items Items to replace it with.
	 */
	void Replace(_In_ DWORD i, _In_ Vector<T> Items) {
		if (!Items.Size() || i >= Size()) return;
		Reserve(Items.Size());
		RELIB_ASSERT(!memmove_s(Buffer::Data() + (i + Items.Size()) * sizeof(T), Buffer::Size() - (i + Items.Size()) * sizeof(T), Buffer::Data() + i * sizeof(T), (nItems - i) * sizeof(T)));
		RELIB_ASSERT(!memcpy_s(Buffer::Data() + i * sizeof(T), Buffer::Size() - i * sizeof(T), Items.Data(), Items.Size() * sizeof(T)));
		ReLibMetrics.Memory.InUse += (Items.Size() - 1) * sizeof(T);
	}

	/*!
	 * @brief Replaces multiple elements with vector.
	 * 
	 * @param [in] i Index to begin replacement.
	 * @param [in] Items Items to replace with.
	 */
	inline void Overwrite(_In_ DWORD i, _In_ Vector<T> Items) {
		RELIB_ASSERT(!memcpy_s(Buffer::Data() + sizeof(T) * i, Buffer::Size() - sizeof(T) * i, Items.Data(), Items.Size() * sizeof(T)));
	}

	/*!
	 * @brief Release memory being used.
	 */
	void Release() {
		Buffer::Release();
		ReLibMetrics.Memory.InUse -= sizeof(T) * nItems;
		nItems = 0;
	}

	/*!
	 * @brief Insert item at index.
	 * 
	 * @param [in] i Index to insert item.
	 * @param [in] Item Item to be inserted.
	 */
	void Insert(_In_ DWORD i, _In_ T Item) {
		if (i > Size()) return;
		if (i == Size()) {
			Push(Item);
			return;
		}
		nItems++;
		Grow();

		// Shift memory
		RELIB_ASSERT(!memmove_s(Buffer::Data() + (i + 1) * sizeof(T), Buffer::Size() - (i + 1) * sizeof(T), Buffer::Data() + i * sizeof(T), (nItems - i - 1) * sizeof(T)));
		
		// Insert item
		operator[](i) = Item;
	}

	/*!
	 * @brief Insert multiple items at index.
	 * 
	 * @param [in] i Index to insert items.
	 * @param [in] Items Items to be inserted.
	 */
	void Insert(_In_ DWORD i, _In_ Vector<T> Items) {
		if (i > Size()) return;

		// Size stuff
		nItems += Items.Size();
		Grow();

		// Add to end
		if (i == Size()) {
			Merge(Items);
		}

		// Shift and insert
		else {
			RELIB_ASSERT(!memmove_s(Buffer::Data() + (i + Items.Size()) * sizeof(T), Buffer::Size() - (i + Items.Size()) * sizeof(T), Buffer::Data() + i * sizeof(T), (nItems - i - Items.Size()) * sizeof(T)));
			RELIB_ASSERT(!memcpy_s(Buffer::Data() + i * sizeof(T), Buffer::Size() - i * sizeof(T), Items.Data(), Items.Size() * sizeof(T)));
			ReLibMetrics.Memory.InUse += Items.Size() * sizeof(T);
		}
	}

	/*!
	 * @brief Remove item at idex.
	 * 
	 * @param [in] i Index to remove item from.
	 */
	void Remove(_In_ DWORD i) {
		if (!Buffer::Data() || !Buffer::Size() || i >= Size()) return;
		RELIB_ASSERT(!memcpy_s(Buffer::Data() + sizeof(T) * i, Buffer::Size() - sizeof(T) * i, Buffer::Data() + sizeof(T) * (i + 1), (nItems * sizeof(T)) - sizeof(T) * (i + 1)));
		nItems--;
		ReLibMetrics.Memory.InUse -= sizeof(T);
	}

	/*!
	 * @brief Finds an item.
	 * 
	 * @param [in] Item Item to search for.
	 * @return Index of item.
	 * @retval -1 Not found.
	 */
	int Find(_In_ T Item) const {
		for (int i = 0, n = Size(); i < n; i++) {
			if (!memcmp(&Item, &operator[](i), sizeof(T))) return i;
		}
		return -1;
	}

	/*!
	 * @brief Checks to see if a matching item exists.
	 * 
	 * @param [in] Item Item to search for.
	 * @retval true Present.
	 * @retval false Not present.
	 */
	inline bool Includes(_In_ T Item) const {
		return Find(Item) >= 0;
	}
};