/*!
 * @file relib.hpp
 * @author undisassemble
 * @brief relib main include
 * @version 0.0.0
 * @date 2025-05-16
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
#ifdef _RELIB_INTERNAL
RELIB_EXPORT void _BaseLogger(const char* message, ...);
typedef struct _ReLibData_t {
	void (__stdcall *ErrorCallback)(const char* message, ...) = _BaseLogger;
	void (__stdcall *WarningCallback)(const char* message, ...) = _BaseLogger;
	void (__stdcall *LoggingCallback)(const char* message, ...) = _BaseLogger;
} ReLibData_t;
extern ReLibData_t ReLibData;
#endif

// Exports
#ifdef __cplusplus
extern "C" {
#endif
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
 */
struct Buffer {
	BYTE* pBytes;     //!< Pointer to raw data.
	uint64_t u64Size; //!< Size of `pBytes`.

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
	RELIB_EXPORT void Allocate(_In_ uint64_t Size);

	/*!
	 * @brief Release memory used by buffer.
	 */
	RELIB_EXPORT void Release();
};

#ifdef __cplusplus
}
#endif

/*!
 * @brief List it items.
 * 
 * @tparam T Type of data stored.
 */
template <typename T>
struct Vector {
	Buffer raw = { 0 };
	DWORD nItems = 0;
	bool bExponentialGrowth : 1 = false; //!< Whether extra memory should be reserved when limit reached, faster on larger vectors.
	bool bCannotBeReleased : 1 = false;  //!< When enabled `Release()` does nothing. Use if the buffer is within another memory block.

	/*!
	 * @brief Reserves additional memory.
	 * @remark Unlike `Buffer::Allocate(_In_ uint64_t Size)`, this is cumulative and adds additional memory.
	 * 
	 * @param [in] nItems Number of items to 
	 */
	void Reserve(_In_ int nItems) {
		raw.Allocate(raw.u64Size + nItems * sizeof(T));
	}

	/*!
	 * @brief Merge with another vector.
	 * 
	 * @param [in] Other Other vector to merge with.
	 * @param [in] bFreeOther Don't free the other vector.
	 */
	void Merge(_In_ Vector<T> Other, _In_ bool bFreeOther = false) {
		raw.u64Size = nItems * sizeof(T);
		raw.Merge(Other.raw, false);
		if (bFreeOther) Other.Release();
		nItems += Other.nItems;
		ReLibMetrics.Memory.InUse += Other.nItems * sizeof(T);
	}

	/*!
	 * @brief Number of items in the vector.
	 * 
	 * @return Number of items.
	 */
	size_t Size() {
		return nItems;
	}

	/*!
	 * @brief Total number of items that can fit before more memory will be reserved.
	 * 
	 * @return Number of items.
	 */
	size_t Capacity() {
		return raw.u64Size / sizeof(T);
	}

	/*!
	 * @brief Reserve memory based on number of items.
	 */
	void Grow() {
		if (bCannotBeReleased) return;

		// Create buffer
		if (raw.u64Size < sizeof(T) || !raw.pBytes || !raw.u64Size) {
			raw.Allocate(sizeof(T) * (bExponentialGrowth ? 10 : 1));
			ZeroMemory(raw.pBytes, raw.u64Size);
		}
		
		// Expand buffer
		else if (raw.u64Size < nItems * sizeof(T)) {
			uint64_t OldSize = raw.u64Size;
			uint64_t NewSize = OldSize;
			if (bExponentialGrowth) {
				while (NewSize < nItems * sizeof(T)) {
					NewSize = sizeof(T) * (NewSize / sizeof(T)) * 1.1;
				}
			} else {
				NewSize = nItems * sizeof(T);
			}
			raw.Allocate(NewSize);
			ZeroMemory(raw.pBytes + OldSize, NewSize - OldSize);
		}
	}

	/*!
	 * @brief Get item at index i.
	 * 
	 * @param [in] i Index.
	 * @return Item.
	 */
	T& At(_In_ DWORD i) {
		// It's better for this to crash than give bad data
		return ((T*)raw.pBytes)[i];
	}

	/*!
	 * @brief Get item at index i.
	 * 
	 * @param [in] i Index.
	 * @return Item.
	 */
	T& operator[](_In_ int i) {
		return ((T*)raw.pBytes)[i];
	}

	/*!
	 * @brief Get item at index i.
	 * 
	 * @param [in] i Index.
	 * @return Item.
	 */
	const T& operator[](_In_ int i) const {
		return ((T*)raw.pBytes)[i];
	}

	/*!
	 * @brief Push item to end of vector.
	 * 
	 * @param [in] Item Item to push.
	 */
	void Push(_In_ T Item) {
		if (bCannotBeReleased) return;
		nItems++;
		Grow();
		memcpy(raw.pBytes + (nItems - 1) * sizeof(T), &Item, sizeof(T));
		ReLibMetrics.Memory.InUse += sizeof(T);
	}

	/*!
	 * @brief Push vector of items to end of vector.
	 * 
	 * @param [in] Items Items to push.
	 */
	void Push(_In_ Vector<T> Items) {
		for (int i = 0; i < Items.Size(); i++) {
			Push(Items[i]);
		}
	}

	/*!
	 * @brief Pop item from end vector.
	 * 
	 * @return Popped item.
	 */
	T Pop() {
		if (!raw.u64Size || !raw.pBytes || bCannotBeReleased) {
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
	 * @brief Replace item at index i.
	 * @deprecated Use `operator[]` instead.
	 * 
	 * @param [in] i Index of item to replace.
	 * @param [in] Item Item to replace it with.
	 */
	void Replace(_In_ DWORD i, _In_ T Item) {
		if (i < Size()) {
			((T*)raw.pBytes)[i] = Item;
		}
	}

	/*!
	 * @brief Replace single element with vector.
	 * 
	 * @param [in] i Index to replace.
	 * @param [in] Items Items to replace it with.
	 */
	void Replace(_In_ DWORD i, _In_ Vector<T> Items) {
		if (!Items.Size() || i >= Size()) return;
		Replace(i, Items[0]);
		Items.nItems--;
		Items.raw.pBytes += sizeof(T);
		Items.raw.u64Size -= sizeof(T);
		Insert(i + 1, Items);
		Items.raw.u64Size += sizeof(T);
		Items.raw.pBytes -= sizeof(T);
		Items.nItems++;
	}

	/*!
	 * @brief Replaces multiple elements with vector.
	 * 
	 * @param [in] i Index to begin replacement.
	 * @param [in] Items Items to replace with.
	 */
	void Overwrite(_In_ DWORD i, _In_ Vector<T> Items) {
		for (int j = 0; j < Items.Size() && i < Size(); j++ && i++) {
			((T*)raw.pBytes)[i] = Items[j];
		}
	}

	/*!
	 * @brief Release memory being used.
	 */
	void Release() {
		if (!bCannotBeReleased) {
			raw.Release();
			ReLibMetrics.Memory.InUse -= sizeof(T) * nItems;
			nItems = 0;
		}
	}

	/*!
	 * @brief Insert item at index.
	 * 
	 * @param [in] i Index to insert item.
	 * @param [in] Item Item to be inserted.
	 */
	void Insert(_In_ DWORD i, _In_ T Item) {
		if (i > Size() || bCannotBeReleased) return;
		if (i == Size()) {
			Push(Item);
			return;
		}
		nItems++;
		Grow();

		// Shift memory
		memmove(raw.pBytes + (i + 1) * sizeof(T), raw.pBytes + i * sizeof(T), (nItems - i - 1) * sizeof(T));
		
		// Insert item
		Replace(i, Item);
	}

	/*!
	 * @brief Insert multiple items at index.
	 * 
	 * @param [in] i Index to insert items.
	 * @param [in] Items Items to be inserted.
	 */
	void Insert(_In_ DWORD i, _In_ Vector<T> Items) {
		if (i > Size() || bCannotBeReleased) return;

		// Size stuff
		nItems += Items.nItems;
		Grow();

		// Add to end
		if (i == Size()) {
			memcpy(raw.pBytes + i * sizeof(T), Items.raw.pBytes, Items.nItems * sizeof(T));
		}

		// Shift and insert
		else {
			memmove(raw.pBytes + (i + Items.nItems) * sizeof(T), raw.pBytes + i * sizeof(T), (nItems - i - Items.nItems) * sizeof(T));
			memcpy(raw.pBytes + i * sizeof(T), Items.raw.pBytes, Items.nItems * sizeof(T));
		}
	}

	/*!
	 * @brief Remove item at idex.
	 * 
	 * @param [in] i Index to remove item from.
	 */
	void Remove(_In_ DWORD i) {
		if (!raw.u64Size || !raw.pBytes || i >= Size() || bCannotBeReleased) return;
		memcpy(raw.pBytes + sizeof(T) * i, raw.pBytes + sizeof(T) * (i + 1), (nItems * sizeof(T)) - sizeof(T) * (i + 1));
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
	int Find(_In_ T Item) {
		for (int i = 0, n = Size(); i < n; i++) {
			if (!memcmp(&Item, &((T*)raw.pBytes)[i], sizeof(T))) return i;
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
	bool Includes(_In_ T Item) {
		return Find(Item) >= 0;
	}
};