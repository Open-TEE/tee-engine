/*****************************************************************************
** Copyright (C) 2013 Secure Systems Group.                                 **
**                                                                          **
** Licensed under the Apache License, Version 2.0 (the "License");          **
** you may not use this file except in compliance with the License.         **
** You may obtain a copy of the License at                                  **
**                                                                          **
**      http://www.apache.org/licenses/LICENSE-2.0                          **
**                                                                          **
** Unless required by applicable law or agreed to in writing, software      **
** distributed under the License is distributed on an "AS IS" BASIS,        **
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. **
** See the License for the specific language governing permissions and      **
** limitations under the License.                                           **
*****************************************************************************/

#ifndef __TEE_STORAGE_API_H__
#define __TEE_STORAGE_API_H__

#include "tee_data_types.h"

/*
 * ## Data Types ##
 */

typedef struct {
	uint32_t attributeID;
	union {
		struct {
			void *buffer;
			size_t length;
		} ref;
		struct {
			uint32_t a, b;
		} value;
	} content;
} TEE_Attribute;

typedef struct {
	uint32_t objectType;
	uint32_t objectSize;
	uint32_t maxObjectSize;
	uint32_t objectUsage;
	uint32_t dataSize;
	uint32_t dataPosition;
	uint32_t handleFlags;
} TEE_ObjectInfo;

/* clang-format off */
typedef enum{
	TEE_DATA_SEEK_SET = 0,
	TEE_DATA_SEEK_CUR,
	TEE_DATA_SEEK_END
} TEE_Whence;

typedef struct __TEE_ObjectHandle* TEE_ObjectHandle;

typedef struct __TEE_ObjectEnumHandle* TEE_ObjectEnumHandle;

/*
 * ## Constants ##
 */

/* Object Storage Constants */
#define TEE_STORAGE_PRIVATE			0x00000001

/* Data Flag Constants */
#define TEE_DATA_FLAG_ACCESS_READ		0x00000001
#define TEE_DATA_FLAG_ACCESS_WRITE		0x00000002
#define TEE_DATA_FLAG_ACCESS_WRITE_META		0x00000004
#define TEE_DATA_FLAG_SHARE_READ		0x00000010
#define TEE_DATA_FLAG_SHARE_WRITE		0x00000020
#define TEE_DATA_FLAG_CREATE			0x00000200
#define TEE_DATA_FLAG_EXCLUSIVE			0x00000400

/* Usage Constants */
#define TEE_USAGE_EXTRACTABLE			0x00000001
#define TEE_USAGE_ENCRYPT			0x00000002
#define TEE_USAGE_DECRYPT			0x00000004
#define TEE_USAGE_MAC				0x00000008
#define TEE_USAGE_SIGN				0x00000010
#define TEE_USAGE_VERIFY			0x00000020
#define TEE_USAGE_DERIVE			0x00000040

/* Handle Flag Constants */
#define TEE_HANDLE_FLAG_PERSISTENT		0x00010000
#define TEE_HANDLE_FLAG_INITIALIZED		0x00020000
#define TEE_HANDLE_FLAG_KEY_SET			0x00040000
#define TEE_HANDLE_FLAG_EXPECT_TWO_KEYS		0x00080000

/* Operation Constants */
#define TEE_OPERATION_CIPHER			1
#define TEE_OPERATION_MAC			3
#define TEE_OPERATION_AE			4
#define TEE_OPERATION_DIGEST			5
#define TEE_OPERATION_ASYMMETRIC_CIPHER		6
#define TEE_OPERATION_ASYMMETRIC_SIGNATURE	7
#define TEE_OPERATION_KEY_DERIVATION		8

/* Miscellaneous Constants */
#define TEE_DATA_MAX_POSITION			0xFFFFFFFF
#define TEE_OBJECT_ID_MAX_LEN			64

/* clang-format on */

/*
 * ## Generic Object Functions ##
 */

/*!
 * \brief TEE_GetObjectInfo
 * \param object
 * \param objectInfo
 */
void TEE_GetObjectInfo(TEE_ObjectHandle object, TEE_ObjectInfo *objectInfo);

/*!
 * \brief TEE_RestrictObjectUsage
 * \param object
 * \param objectUsage
 */
void TEE_RestrictObjectUsage(TEE_ObjectHandle object, uint32_t objectUsage);

/*!
 * \brief TEE_GetObjectBufferAttribute
 * \param object
 * \param attributeID
 * \param buffer
 * \param size
 * \return
 */
TEE_Result TEE_GetObjectBufferAttribute(TEE_ObjectHandle object, uint32_t attributeID, void *buffer,
					size_t *size);

/*!
 * \brief TEE_GetObjectValueAttribute
 * \param object
 * \param attributeID
 * \param a
 * \param b
 * \return
 */
TEE_Result TEE_GetObjectValueAttribute(TEE_ObjectHandle object, uint32_t attributeID, uint32_t *a,
				       uint32_t *b);

/*!
 * \brief TEE_CloseObject
 * \param object
 */
void TEE_CloseObject(TEE_ObjectHandle object);

/*
 * ## Transient Object Functions ##
 */

/*!
 * \brief TEE_AllocateTransientObject
 * \param objectType
 * \param maxObjectSize
 * \param object
 * \return
 */
TEE_Result TEE_AllocateTransientObject(uint32_t objectType, uint32_t maxObjectSize,
				       TEE_ObjectHandle *object);

/*!
 * \brief TEE_FreeTransientObject
 * \param object
 */
void TEE_FreeTransientObject(TEE_ObjectHandle object);

/*!
 * \brief TEE_ResetTransientObject
 * \param object
 */
void TEE_ResetTransientObject(TEE_ObjectHandle object);

/*!
 * \brief TEE_PopulateTransientObject
 * \param object
 * \param attrs
 * \param attrCount
 * \return
 */
TEE_Result TEE_PopulateTransientObject(TEE_ObjectHandle object, TEE_Attribute *attrs,
				       uint32_t attrCount);

/*!
 * \brief TEE_InitRefAttribute
 * \param attr
 * \param attributeID
 * \param buffer
 * \param length
 */
void TEE_InitRefAttribute(TEE_Attribute *attr, uint32_t attributeID, void *buffer, size_t length);

/*!
 * \brief TEE_InitValueAttribute
 * \param attr
 * \param attributeID
 * \param a
 * \param b
 */
void TEE_InitValueAttribute(TEE_Attribute *attr, uint32_t attributeID, uint32_t a, uint32_t b);

/*!
 * \brief TEE_CopyObjectAttributes
 * \param destObject
 * \param srcObject
 */
void TEE_CopyObjectAttributes(TEE_ObjectHandle destObject, TEE_ObjectHandle srcObject);

/*!
 * \brief TEE_GenerateKey
 * \param object
 * \param keySize
 * \param params
 * \param paramCount
 * \return
 */
TEE_Result TEE_GenerateKey(TEE_ObjectHandle object, uint32_t keySize, TEE_Attribute *params,
			   uint32_t paramCount);

/*
 * ## Persistent Object Functions ##
 */

/*!
 * \brief TEE_OpenPersistentObject
 * \param storageID
 * \param objectID
 * \param objectIDLen
 * \param flags
 * \param object
 * \return
 */
TEE_Result TEE_OpenPersistentObject(uint32_t storageID, void *objectID, size_t objectIDLen,
				    uint32_t flags, TEE_ObjectHandle *object);

/*!
 * \brief TEE_CreatePersistentObject
 * \param storageID
 * \param objectID
 * \param objectIDLen
 * \param flags
 * \param attributes
 * \param initialData
 * \param initialDataLen
 * \param object
 * \return
 */
TEE_Result TEE_CreatePersistentObject(uint32_t storageID, void *objectID, size_t objectIDLen,
				      uint32_t flags, TEE_ObjectHandle attributes,
				      void *initialData, size_t initialDataLen,
				      TEE_ObjectHandle *object);

/*!
 * \brief TEE_CloseAndDeletePersistentObject
 * \param object
 */
void TEE_CloseAndDeletePersistentObject(TEE_ObjectHandle object);

/*!
 * \brief TEE_RenamePersistentObject
 * \param object
 * \param newObjectID
 * \param newObjectIDLen
 * \return
 */
TEE_Result TEE_RenamePersistentObject(TEE_ObjectHandle object, void *newObjectID,
				      size_t newObjectIDLen);

/*
 * ## Persistent Object Enumeration Functions ##
 */

/*!
 * \brief TEE_AllocatePersistentObjectEnumerator
 * \param objectEnumerator
 * \return
 */
TEE_Result TEE_AllocatePersistentObjectEnumerator(TEE_ObjectEnumHandle *objectEnumerator);

/*!
 * \brief TEE_FreePersistentObjectEnumerator
 * \param objectEnumerator
 */
void TEE_FreePersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator);

/*!
 * \brief TEE_ResetPersistentObjectEnumerator
 * \param objectEnumerator
 */
void TEE_ResetPersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator);

/*!
 * \brief TEE_StartPersistentObjectEnumerator
 * \param objectEnumerator
 * \param storageID
 * \return
 */
TEE_Result TEE_StartPersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator,
					       uint32_t storageID);

/*!
 * \brief TEE_GetNextPersistentObject
 * \param objectEnumerator
 * \param objectInfo
 * \param objectID
 * \param objectIDLen
 * \return
 */
TEE_Result TEE_GetNextPersistentObject(TEE_ObjectEnumHandle objectEnumerator,
				       TEE_ObjectInfo *objectInfo, void *objectID,
				       size_t *objectIDLen);

/*
 * ## Data Stream Access Functions ##
 */

/*!
 * \brief TEE_ReadObjectData
 * \param object
 * \param buffer
 * \param size
 * \param count
 * \return
 */
TEE_Result TEE_ReadObjectData(TEE_ObjectHandle object, void *buffer, size_t size, uint32_t *count);

/*!
 * \brief TEE_WriteObjectData
 * \param object
 * \param buffer
 * \param size
 * \return
 */
TEE_Result TEE_WriteObjectData(TEE_ObjectHandle object, void *buffer, size_t size);

/*!
 * \brief TEE_TruncateObjectData
 * \param object
 * \param size
 * \return
 */
TEE_Result TEE_TruncateObjectData(TEE_ObjectHandle object, uint32_t size);

/*!
 * \brief TEE_SeekObjectData
 * \param object
 * \param offset
 * \param whence
 * \return
 */
TEE_Result TEE_SeekObjectData(TEE_ObjectHandle object, int32_t offset, TEE_Whence whence);

#endif /* __TEE_STORAGE_API_H__ */
