#include <Guid/GlobalVariable.h>
#include <IndustryStandard/Tpm20.h>
#include <Library/BaseCryptLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/Tpm2CommandLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Protocol/DevicePathToText.h>
#include <Protocol/Tcg2Protocol.h>
#include <Protocol/UsbIo.h>
#include <Uefi.h>
#include <IndustryStandard/UefiTcgPlatform.h>

#define RECOVERY_CODE_LENGTH 20
#define TPM_HASH_ALGO TPM_ALG_SHA256
// #define TPM_HASH_SIZE SHA256_DIGEST_SIZE

#define USB_SERIAL_NV_INDEX 0x01510000
#define USB_HASH_NV_INDEX 0x01510001
#define TPM_HASH_ALGO TPM_ALG_SHA256
#define TPM_HASH_SIZE 32
#define MAX_USB_SERIAL_LEN 128
#define MAX_SERIAL_LENGTH 128

#define COMBINED_STORAGE_SIZE sizeof(COMBINED_STORAGE) // 65 bytes total


#define DXEHASH_NVRAM_GUID \
    {0x12345678, 0x9abc, 0xdef0, {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}}
    
/**
#define RANDOMHASH_NVRAM_GUID \
    {0x12345677, 0x9bbc, 0xdef0, {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}}

#define HASHINFO_NVRAM_GUID \
    {0x12345432, 0x9abc, 0xdef0, {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}}
**/
//STATIC EFI_GUID gHashInfoNvramGuid = HASHINFO_NVRAM_GUID;

STATIC EFI_GUID gDxeHashNvramGuid = DXEHASH_NVRAM_GUID;

//STATIC EFI_GUID gRandomHashNvramGuid = RANDOMHASH_NVRAM_GUID;

#define NVRAM_VARIABLE_ATTRIBUTES                                  \
    (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | \
     EFI_VARIABLE_RUNTIME_ACCESS)


#pragma pack(1)
typedef struct
{
    TPM2_COMMAND_HEADER Header;
    UINT16 bytesRequested;
} TPM2_GET_RANDOM_COMMAND;

typedef struct
{
    TPM2_RESPONSE_HEADER Header;
    TPM2B_DIGEST randomBytes;
} TPM2_GET_RANDOM_RESPONSE;
#pragma pack()
/**
// Structure to store USB device details in NVRAM
typedef struct
{
    UINT16 Vid;
    UINT16 Pid;
    CHAR16 SerialNumber[128]; // Max serial number length
    UINT8 Flag;               // 0 = not registered, 1 = registered
    //UINT8 Hash[32];
    //UINT8 HashValid;
    //UINT8 NewHash[32];
} USB_DEVICE_INFO;
**/

typedef struct
{
    UINT16 Vid;                              ///< Vendor ID
    UINT16 Pid;                              ///< Product ID
    CHAR16 SerialNumber[MAX_USB_SERIAL_LEN]; ///< Serial Number (Unicode)
    UINT8 Hash[TPM_HASH_SIZE];               ///< Generated Hash
    UINT8 RecoveryHash[TPM_HASH_SIZE];
    UINT8 Flag;
} USB_DEVICE;

// Structure to store USB Serial
typedef struct
{
    CHAR8 SerialNumber[MAX_SERIAL_LENGTH];
} TPM_USB_SERIAL_STORAGE;

/**
typedef struct
{
    UINT8 Hash[32];
    UINT8 NewHash[32];
} HASH_INFO;


typedef struct
{
    UINT8 RandomNumHash[32];
} RND_HASH_INFO;
*/

// Check main USB device variable
USB_DEVICE StoredDevice = {0};
UINTN DataSize = sizeof(USB_DEVICE);
// Status = gRT->GetVariable(L"DxeHashUsbDevice", &gDxeHashNvramGuid, NULL, &DataSize, &StoredDevice);

typedef struct
{
    UINT8 Flag;                        // 1 byte - status/flag value
    UINT8 UsbHash[TPM_HASH_SIZE];      // 32 bytes - USB device hash
    UINT8 RecoveryHash[TPM_HASH_SIZE]; // 32 bytes - recovery hash
} COMBINED_STORAGE;

EFI_STATUS
EFIAPI
Tpm2SubmitCommandC(
    IN UINT32 InputSize,
    IN UINT8 *InputBuffer,
    OUT UINT32 *OutputSize,
    OUT UINT8 *OutputBuffer)
{
    EFI_STATUS Status;
    EFI_TCG2_PROTOCOL *Tcg2Protocol;

    // Locate the TCG2 protocol - the interface for communicating with the TPM
    Status = gBS->LocateProtocol(
        &gEfiTcg2ProtocolGuid,
        NULL,
        (VOID **)&Tcg2Protocol);
    if (EFI_ERROR(Status))
    {
        DEBUG((DEBUG_ERROR, "Failed to locate TCG2 protocol: %r\n", Status));
        return Status;
    }
    Status = Tcg2Protocol->SubmitCommand(
        Tcg2Protocol,
        InputSize,
        InputBuffer,
        *OutputSize,
        OutputBuffer);

    return Status;
}

EFI_STATUS
EFIAPI
TestTpmConnection(
    VOID)
{
    EFI_STATUS Status;
    EFI_TCG2_PROTOCOL *Tcg2Protocol;
    UINT8 CmdBuffer[64];
    UINT32 CmdSize;
    UINT8 RespBuffer[256];
    UINT32 RespSize = sizeof(RespBuffer);
    TPM2_COMMAND_HEADER *CmdHeader;
    TPM2_RESPONSE_HEADER *RespHeader;

    Status = gBS->LocateProtocol(
        &gEfiTcg2ProtocolGuid,
        NULL,
        (VOID **)&Tcg2Protocol);
    if (EFI_ERROR(Status))
    {
        Print(L"Failed to locate TCG2 protocol: %r\n", Status);
        return Status;
    }

    ZeroMem(CmdBuffer, sizeof(CmdBuffer));
    CmdHeader = (TPM2_COMMAND_HEADER *)CmdBuffer;

    CmdHeader->tag = SwapBytes16(TPM_ST_NO_SESSIONS);
    CmdHeader->commandCode = SwapBytes32(TPM_CC_GetCapability);

    *(UINT32 *)(CmdBuffer + sizeof(TPM2_COMMAND_HEADER)) = SwapBytes32(TPM_CAP_TPM_PROPERTIES);

    *(UINT32 *)(CmdBuffer + sizeof(TPM2_COMMAND_HEADER) + sizeof(UINT32)) =
        SwapBytes32(TPM_PT_MANUFACTURER);

    *(UINT32 *)(CmdBuffer + sizeof(TPM2_COMMAND_HEADER) + sizeof(UINT32) + sizeof(UINT32)) =
        SwapBytes32(1);

    CmdSize = sizeof(TPM2_COMMAND_HEADER) + sizeof(UINT32) + sizeof(UINT32) + sizeof(UINT32);
    CmdHeader->paramSize = SwapBytes32(CmdSize);

    DEBUG((DEBUG_INFO, "Testing TPM connection with GetCapability command...\n"));

    Status = Tcg2Protocol->SubmitCommand(
        Tcg2Protocol,
        CmdSize,
        CmdBuffer,
        RespSize,
        RespBuffer);

    if (EFI_ERROR(Status))
    {
        Print(L"TPM communication test failed: %r\n", Status);
        Print(L"This indicates a fundamental TPM connectivity problem.\n");
        return Status;
    }

    RespHeader = (TPM2_RESPONSE_HEADER *)RespBuffer;
    UINT32 ResponseCode = SwapBytes32(RespHeader->responseCode);

    if (ResponseCode != TPM_RC_SUCCESS)
    {
        Print(L"TPM communication test returned error: 0x%x\n", ResponseCode);
        return EFI_DEVICE_ERROR;
    }
    DEBUG((DEBUG_INFO, "TPM communication test successful!\n"));
    return EFI_SUCCESS;
}

// Define NV space for USB serial numbers at index 0x01510000
EFI_STATUS
EFIAPI
DefineSerialIndex(
    VOID)
{
    EFI_STATUS Status;
    EFI_TCG2_PROTOCOL *Tcg2Protocol;
    UINT8 CmdBuffer[1024];
    UINT32 CmdSize = 0;
    UINT8 RespBuffer[1024];
    UINT32 RespSize = sizeof(RespBuffer);
    TPM2_COMMAND_HEADER *CmdHeader;
    TPM2_RESPONSE_HEADER *RespHeader;

    Status = TestTpmConnection();
    if (EFI_ERROR(Status))
    {
        Print(L"TPM connection test failed, cannot proceed with serial NV space definition\n");
        return Status;
    }

    Status = gBS->LocateProtocol(
        &gEfiTcg2ProtocolGuid,
        NULL,
        (VOID **)&Tcg2Protocol);
    if (EFI_ERROR(Status))
    {
        Print(L"Failed to locate TCG2 protocol: %r\n", Status);
        return Status;
    }

    ZeroMem(CmdBuffer, sizeof(CmdBuffer));
    ZeroMem(RespBuffer, sizeof(RespBuffer));

    CmdHeader = (TPM2_COMMAND_HEADER *)CmdBuffer;
    CmdHeader->tag = SwapBytes16(TPM_ST_SESSIONS);
    CmdHeader->commandCode = SwapBytes32(TPM_CC_NV_DefineSpace);
    CmdSize = sizeof(TPM2_COMMAND_HEADER);

    *(UINT32 *)(CmdBuffer + CmdSize) = SwapBytes32(TPM_RH_OWNER);
    CmdSize += sizeof(UINT32);

    UINT32 authAreaSizeOffset = CmdSize;
    CmdSize += sizeof(UINT32); // Reserve space for auth size
    UINT32 authAreaStartOffset = CmdSize;

    *(UINT32 *)(CmdBuffer + CmdSize) = SwapBytes32(TPM_RS_PW);
    CmdSize += sizeof(UINT32);

    *(UINT16 *)(CmdBuffer + CmdSize) = SwapBytes16(0); // nonce.size = 0
    CmdSize += sizeof(UINT16);

    CmdBuffer[CmdSize] = 0; // No session attributes set
    CmdSize += 1;

    *(UINT16 *)(CmdBuffer + CmdSize) = SwapBytes16(0); // hmac.size = 0
    CmdSize += sizeof(UINT16);

    UINT32 authAreaSize = CmdSize - authAreaStartOffset;
    *(UINT32 *)(CmdBuffer + authAreaSizeOffset) = SwapBytes32(authAreaSize);

    *(UINT16 *)(CmdBuffer + CmdSize) = SwapBytes16(0); // auth.size = 0
    CmdSize += sizeof(UINT16);

    UINT16 publicInfoSizeOffset = CmdSize;
    CmdSize += sizeof(UINT16); // Reserve space for size
    UINT32 publicInfoStartOffset = CmdSize;

    *(UINT32 *)(CmdBuffer + CmdSize) = SwapBytes32(USB_SERIAL_NV_INDEX); // Use 0x01510000
    CmdSize += sizeof(UINT32);

    *(UINT16 *)(CmdBuffer + CmdSize) = SwapBytes16(TPM_ALG_SHA256);
    CmdSize += sizeof(UINT16);

    *(UINT32 *)(CmdBuffer + CmdSize) = SwapBytes32(0x00020002);
    CmdSize += sizeof(UINT32);

    *(UINT16 *)(CmdBuffer + CmdSize) = SwapBytes16(0); // authPolicy.size = 0
    CmdSize += sizeof(UINT16);

    *(UINT16 *)(CmdBuffer + CmdSize) = SwapBytes16(128); // Size for serial storage
    CmdSize += sizeof(UINT16);

    UINT16 publicInfoSize = CmdSize - publicInfoStartOffset;
    *(UINT16 *)(CmdBuffer + publicInfoSizeOffset) = SwapBytes16(publicInfoSize);

    CmdHeader->paramSize = SwapBytes32(CmdSize);

   // Print(L"Define TPM NVRAM index at 0x%08X for Usb serial number storage of size %d bytes\n", USB_SERIAL_NV_INDEX, 128);
   DEBUG((DEBUG_INFO,"Define TPM NVRAM index at 0x%08X for Usb serial number storage of size %d bytes\n", USB_SERIAL_NV_INDEX, 128));
    Status = Tcg2Protocol->SubmitCommand(
        Tcg2Protocol,
        CmdSize,
        CmdBuffer,
        RespSize,
        RespBuffer);

    if (EFI_ERROR(Status))
    {
        Print(L"TPM command submission failed: %r\n", Status);
        return Status;
    }

    RespHeader = (TPM2_RESPONSE_HEADER *)RespBuffer;
    UINT32 responseCode = SwapBytes32(RespHeader->responseCode);

    if (responseCode != TPM_RC_SUCCESS)
    {
        DEBUG((DEBUG_INFO, "TPM returned error code for serial space: 0x%x\n", responseCode));

        if (responseCode == TPM_RC_NV_DEFINED)
        {
            DEBUG((DEBUG_INFO, "Serial NV Index 0x%08X already defined.\n", USB_SERIAL_NV_INDEX));
        }
        else if (responseCode == TPM_RC_NV_SPACE)
        {
            Print(L"Insufficient space for serial NV allocation.\n");
        }
        else if (responseCode == TPM_RC_ATTRIBUTES)
        {
            Print(L"Serial NV attributes are not valid for the index type.\n");
        }
        return EFI_DEVICE_ERROR;
    }
    Print(L"TPM serial NV space defined successfully at 0x%08X!\n", USB_SERIAL_NV_INDEX);
    return EFI_SUCCESS;
}

// Define NV space for combined storage at index 0x01510001
EFI_STATUS
EFIAPI
DefineCombinedIndex(
    VOID)
{
    EFI_STATUS Status;
    EFI_TCG2_PROTOCOL *Tcg2Protocol;
    UINT8 CmdBuffer[1024];
    UINT32 CmdSize = 0;
    UINT8 RespBuffer[1024];
    UINT32 RespSize = sizeof(RespBuffer);
    TPM2_COMMAND_HEADER *CmdHeader;
    TPM2_RESPONSE_HEADER *RespHeader;

    Status = TestTpmConnection();
    if (EFI_ERROR(Status))
    {
        Print(L"TPM connection test failed, cannot proceed with combined NV space definition\n");
        return Status;
    }

    Status = gBS->LocateProtocol(
        &gEfiTcg2ProtocolGuid,
        NULL,
        (VOID **)&Tcg2Protocol);
    if (EFI_ERROR(Status))
    {
        Print(L"Failed to locate TCG2 protocol: %r\n", Status);
        return Status;
    }

    ZeroMem(CmdBuffer, sizeof(CmdBuffer));
    ZeroMem(RespBuffer, sizeof(RespBuffer));

    CmdHeader = (TPM2_COMMAND_HEADER *)CmdBuffer;
    CmdHeader->tag = SwapBytes16(TPM_ST_SESSIONS);
    CmdHeader->commandCode = SwapBytes32(TPM_CC_NV_DefineSpace);
    CmdSize = sizeof(TPM2_COMMAND_HEADER);

    *(UINT32 *)(CmdBuffer + CmdSize) = SwapBytes32(TPM_RH_OWNER);
    CmdSize += sizeof(UINT32);

    UINT32 authAreaSizeOffset = CmdSize;
    CmdSize += sizeof(UINT32); // Reserve space for auth size
    UINT32 authAreaStartOffset = CmdSize;

    *(UINT32 *)(CmdBuffer + CmdSize) = SwapBytes32(TPM_RS_PW);
    CmdSize += sizeof(UINT32);

    *(UINT16 *)(CmdBuffer + CmdSize) = SwapBytes16(0); // nonce.size = 0
    CmdSize += sizeof(UINT16);

    CmdBuffer[CmdSize] = 0; // No session attributes set
    CmdSize += 1;

    *(UINT16 *)(CmdBuffer + CmdSize) = SwapBytes16(0); // hmac.size = 0
    CmdSize += sizeof(UINT16);

    UINT32 authAreaSize = CmdSize - authAreaStartOffset;
    *(UINT32 *)(CmdBuffer + authAreaSizeOffset) = SwapBytes32(authAreaSize);

    *(UINT16 *)(CmdBuffer + CmdSize) = SwapBytes16(0); // auth.size = 0
    CmdSize += sizeof(UINT16);

    UINT16 publicInfoSizeOffset = CmdSize;
    CmdSize += sizeof(UINT16); // Reserve space for size
    UINT32 publicInfoStartOffset = CmdSize;

    *(UINT32 *)(CmdBuffer + CmdSize) = SwapBytes32(USB_HASH_NV_INDEX); // Use 0x01510001
    CmdSize += sizeof(UINT32);

    *(UINT16 *)(CmdBuffer + CmdSize) = SwapBytes16(TPM_ALG_SHA256);
    CmdSize += sizeof(UINT16);

    *(UINT32 *)(CmdBuffer + CmdSize) = SwapBytes32(0x00020002); // OWNERWRITE | OWNERREAD
    CmdSize += sizeof(UINT32);

    *(UINT16 *)(CmdBuffer + CmdSize) = SwapBytes16(0); // authPolicy.size = 0
    CmdSize += sizeof(UINT16);

    *(UINT16 *)(CmdBuffer + CmdSize) = SwapBytes16(COMBINED_STORAGE_SIZE); // 68 bytes for combined storage
    CmdSize += sizeof(UINT16);

    UINT16 publicInfoSize = CmdSize - publicInfoStartOffset;
    *(UINT16 *)(CmdBuffer + publicInfoSizeOffset) = SwapBytes16(publicInfoSize);

    CmdHeader->paramSize = SwapBytes32(CmdSize);

   // Print(L"Define TPM NVRAM index at 0x%08X for combined storage of size %d bytes\n", USB_HASH_NV_INDEX, COMBINED_STORAGE_SIZE);
   DEBUG((DEBUG_INFO,"Define TPM NVRAM index at 0x%08X for combined storage of size %d bytes\n", USB_HASH_NV_INDEX, COMBINED_STORAGE_SIZE));
    Status = Tcg2Protocol->SubmitCommand(
        Tcg2Protocol,
        CmdSize,
        CmdBuffer,
        RespSize,
        RespBuffer);

    if (EFI_ERROR(Status))
    {
        Print(L"TPM command submission failed: %r\n", Status);
        return Status;
    }

    RespHeader = (TPM2_RESPONSE_HEADER *)RespBuffer;
    UINT32 responseCode = SwapBytes32(RespHeader->responseCode);

    if (responseCode != TPM_RC_SUCCESS)
    {
        DEBUG((DEBUG_INFO, "TPM returned error code for combined space: 0x%x\n", responseCode));

        if (responseCode == TPM_RC_NV_DEFINED)
        {
            DEBUG((DEBUG_INFO, "Combined NV Index 0x%08X already defined.\n", USB_HASH_NV_INDEX));
        }
        else if (responseCode == TPM_RC_NV_SPACE)
        {
            Print(L"Insufficient space for combined NV allocation.\n");
        }
        else if (responseCode == TPM_RC_ATTRIBUTES)
        {
            Print(L"Combined NV attributes are not valid for the index type.\n");
        }
        return EFI_DEVICE_ERROR;
    }

    Print(L"TPM combined NV space defined successfully at 0x%08X!\n", USB_HASH_NV_INDEX);
    return EFI_SUCCESS;
}

// Helper function to convert Unicode serial to ASCII for TPM storage
EFI_STATUS
ConvertUsbSerialForTpm(
    IN CHAR16 *UnicodeSerial,
    OUT CHAR8 *AsciiSerial,
    IN UINTN AsciiBufferSize)
{
    EFI_STATUS Status;
    UINTN UnicodeLen;
    UINTN ConvertedLen;

    if (UnicodeSerial == NULL || AsciiSerial == NULL || AsciiBufferSize == 0)
    {
        return EFI_INVALID_PARAMETER;
    }

    UnicodeLen = StrLen(UnicodeSerial);
    if (UnicodeLen == 0)
    {
        AsciiSerial[0] = '\0';
        return EFI_SUCCESS;
    }

    Status = UnicodeStrToAsciiStrS(
        UnicodeSerial,
        AsciiSerial,
        AsciiBufferSize);

    if (EFI_ERROR(Status))
    {
        DEBUG((DEBUG_ERROR, "Failed to convert Unicode to ASCII: %r\n", Status));
        return Status;
    }

    ConvertedLen = AsciiStrLen(AsciiSerial);
    DEBUG((DEBUG_INFO, "Converted serial: %a (length: %u)\n", AsciiSerial, ConvertedLen));

    return EFI_SUCCESS;
}

// Helper function to convert ASCII serial from TPM back to Unicode
EFI_STATUS
ConvertTpmSerialToUnicode(
    IN CHAR8 *AsciiSerial,
    OUT CHAR16 *UnicodeSerial,
    IN UINTN UnicodeBufferSize)
{
    EFI_STATUS Status;
    UINTN AsciiLen;

    if (AsciiSerial == NULL || UnicodeSerial == NULL || UnicodeBufferSize == 0)
    {
        return EFI_INVALID_PARAMETER;
    }

    AsciiLen = AsciiStrLen(AsciiSerial);
    if (AsciiLen == 0)
    {
        UnicodeSerial[0] = L'\0';
        return EFI_SUCCESS;
    }

    Status = AsciiStrToUnicodeStrS(
        AsciiSerial,
        UnicodeSerial,
        UnicodeBufferSize / sizeof(CHAR16));

    if (EFI_ERROR(Status))
    {
        DEBUG((DEBUG_ERROR, "Failed to convert ASCII to Unicode: %r\n", Status));
        return Status;
    }

    DEBUG((DEBUG_INFO, "Converted serial back to Unicode: %s\n", UnicodeSerial));

    return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
StoreUsbSerialInTpm(
    IN CHAR16 *SerialFromUsb)
{
    EFI_STATUS Status;
    TPMS_AUTH_COMMAND *AuthSession = NULL;
    TPM2B_MAX_BUFFER *InData = NULL;
    TPM2B_NV_PUBLIC NvPublic;
    UINTN WriteSize;
    TPM_USB_SERIAL_STORAGE TmpStorage;
    TPM2B_NAME NvName;

    if (SerialFromUsb == NULL)
    {
        return EFI_INVALID_PARAMETER;
    }

    //Print(L"\nStoring USB Serial number in TPM at 0x%08X\n", USB_SERIAL_NV_INDEX);
    DEBUG((DEBUG_INFO, "Storing USB serial: %s\n", SerialFromUsb));

    // Convert serial to ASCII format suitable for TPM storage
    ZeroMem(&TmpStorage, sizeof(TPM_USB_SERIAL_STORAGE));
    Status = ConvertUsbSerialForTpm(
        SerialFromUsb,
        TmpStorage.SerialNumber,
        MAX_SERIAL_LENGTH);
    if (EFI_ERROR(Status))
    {
        Print(L"Failed to convert serial for TPM storage: %r\n", Status);
        return Status;
    }

    // Step 1: Read NV index properties (especially size)
    Status = Tpm2NvReadPublic(USB_SERIAL_NV_INDEX, &NvPublic, &NvName);
    if (EFI_ERROR(Status))
    {
        Print(L"Failed to read NV public: %r\n", Status);
        return Status;
    }

    WriteSize = NvPublic.nvPublic.dataSize;
    if (WriteSize == 0 || WriteSize > sizeof(TPM2B_MAX_BUFFER))
    {
        Print(L"Invalid NV index size: %u\n", WriteSize);
        return EFI_BAD_BUFFER_SIZE;
    }

    if (WriteSize < sizeof(TmpStorage))
    {
        Print(L"Defined NV space (%u bytes) is too small for serial (%u bytes)\n", WriteSize, sizeof(TmpStorage));
        return EFI_BAD_BUFFER_SIZE;
    }

    // Allocate TPM structures
    AuthSession = AllocateZeroPool(sizeof(TPMS_AUTH_COMMAND));
    InData = AllocateZeroPool(sizeof(TPM2B_MAX_BUFFER));
    if (AuthSession == NULL || InData == NULL)
    {
        Status = EFI_OUT_OF_RESOURCES;
        goto Cleanup;
    }

    // Setup write buffer
    InData->size = sizeof(TmpStorage);
    CopyMem(InData->buffer, &TmpStorage, InData->size);

    // Setup auth session
    AuthSession->sessionHandle = TPM_RS_PW;
    AuthSession->nonce.size = 0;
    *(UINT8 *)&AuthSession->sessionAttributes = 0;
    AuthSession->hmac.size = 0;

    // Write to TPM
    Status = Tpm2NvWrite(
        TPM_RH_OWNER,
        USB_SERIAL_NV_INDEX,
        AuthSession,
        InData,
        0 // offset
    );

    if (EFI_ERROR(Status))
    {
        Print(L"Failed to write serial to TPM: %r\n", Status);
        goto Cleanup;
    }

   // Print(L"Successfully stored USB serial number in TPM NVRAM at index 0x%08X\n", USB_SERIAL_NV_INDEX);
    DEBUG((DEBUG_INFO, "Successfully stored USB serial in TPM NVRAM at Index 0x%08X\n",USB_SERIAL_NV_INDEX));

Cleanup:
    if (AuthSession)
        FreePool(AuthSession);
    if (InData)
        FreePool(InData);
    return Status;
}

// Function to store combined data (flag, USB hash, recovery hash) in TPM NVRAM at 0x01510001
EFI_STATUS
EFIAPI
StoreCombinedDataInTpm(
    IN UINT8 Flag,
    IN UINT8 *UsbHash OPTIONAL,
    IN UINT8 *RecoveryHash  OPTIONAL
)
{
    EFI_STATUS Status;
    TPMS_AUTH_COMMAND *AuthSession = NULL;
    TPM2B_MAX_BUFFER *InData = NULL;
    TPM2B_NV_PUBLIC NvPublic;
    UINTN WriteSize;
    COMBINED_STORAGE CombinedData;
    TPM2B_NAME NvName;

    if (UsbHash == NULL || RecoveryHash == NULL)
    {
        return EFI_INVALID_PARAMETER;
    }

   // Print(L"\nStoring combined data in TPM at 0x%08X\n", USB_HASH_NV_INDEX);
    DEBUG((DEBUG_INFO, "Storing Flag=%d, UsbHash and RecoveryHash\n", Flag));

    // Prepare combined storage structure
    ZeroMem(&CombinedData, sizeof(COMBINED_STORAGE));
    CombinedData.Flag = Flag;
    CopyMem(CombinedData.UsbHash, UsbHash, TPM_HASH_SIZE);
    CopyMem(CombinedData.RecoveryHash, RecoveryHash, TPM_HASH_SIZE);

    // Step 1: Read NV index properties
    Status = Tpm2NvReadPublic(USB_HASH_NV_INDEX, &NvPublic, &NvName);
    if (EFI_ERROR(Status))
    {
        Print(L"Failed to read combined NV public: %r\n", Status);
        return Status;
    }

    WriteSize = NvPublic.nvPublic.dataSize;
    if (WriteSize < sizeof(COMBINED_STORAGE))
    {
        Print(L"Defined NV space (%u bytes) is too small for combined data (%u bytes)\n",
              WriteSize, sizeof(COMBINED_STORAGE));
        return EFI_BAD_BUFFER_SIZE;
    }

    // Allocate TPM structures
    AuthSession = AllocateZeroPool(sizeof(TPMS_AUTH_COMMAND));
    InData = AllocateZeroPool(sizeof(TPM2B_MAX_BUFFER));
    if (AuthSession == NULL || InData == NULL)
    {
        Status = EFI_OUT_OF_RESOURCES;
        goto Cleanup;
    }

    // Setup write buffer
    InData->size = sizeof(COMBINED_STORAGE);
    CopyMem(InData->buffer, &CombinedData, InData->size);

    // Setup auth session
    AuthSession->sessionHandle = TPM_RS_PW;
    AuthSession->nonce.size = 0;
    *(UINT8 *)&AuthSession->sessionAttributes = 0;
    AuthSession->hmac.size = 0;

    // Write to TPM
    Status = Tpm2NvWrite(
        TPM_RH_OWNER,
        USB_HASH_NV_INDEX,
        AuthSession,
        InData,
        0 // offset
    );

    if (EFI_ERROR(Status))
    {
        Print(L"Failed to write combined data to TPM: %r\n", Status);
        goto Cleanup;
    }

    Print(L"\nSuccessfully stored combined data in TPM NVRAM");
    DEBUG((DEBUG_INFO, "Successfully stored combined data in TPM NVRAM\n"));

Cleanup:
    if (AuthSession)
        FreePool(AuthSession);
    if (InData)
        FreePool(InData);
    return Status;
}

// Function to read combined data from TPM NVRAM
EFI_STATUS
EFIAPI
ReadCombinedDataFromTpm(
    OUT UINT8 *Flag,
    OUT UINT8 *UsbHash,
    OUT UINT8 *RecoveryHash)
{
    EFI_STATUS Status;
    TPMS_AUTH_COMMAND *AuthSession = NULL;
    TPM2B_MAX_BUFFER *OutData = NULL;
    TPM2B_NV_PUBLIC NvPublic;
    UINTN ReadSize;
    COMBINED_STORAGE *CombinedData;
    TPM2B_NAME NvName;

    if (Flag == NULL || UsbHash == NULL || RecoveryHash == NULL)
    {
        return EFI_INVALID_PARAMETER;
    }

    DEBUG((DEBUG_INFO, "Reading combined data from TPM at 0x%08X\n", USB_HASH_NV_INDEX));

    // Step 1: Read NV index properties
    Status = Tpm2NvReadPublic(USB_HASH_NV_INDEX, &NvPublic, &NvName);
    if (EFI_ERROR(Status))
    {
        DEBUG((DEBUG_ERROR, "Failed to read combined NV public: %r\n", Status));
        return Status;
    }

    ReadSize = NvPublic.nvPublic.dataSize;
    if (ReadSize < sizeof(COMBINED_STORAGE))
    {
        DEBUG((DEBUG_ERROR, "NV space size (%u) smaller than expected (%u)\n",
               ReadSize, sizeof(COMBINED_STORAGE)));
        return EFI_BAD_BUFFER_SIZE;
    }

    // Allocate TPM structures
    AuthSession = AllocateZeroPool(sizeof(TPMS_AUTH_COMMAND));
    OutData = AllocateZeroPool(sizeof(TPM2B_MAX_BUFFER));
    if (AuthSession == NULL || OutData == NULL)
    {
        Status = EFI_OUT_OF_RESOURCES;
        goto Cleanup;
    }

    // Setup auth session
    AuthSession->sessionHandle = TPM_RS_PW;
    AuthSession->nonce.size = 0;
    *(UINT8 *)&AuthSession->sessionAttributes = 0;
    AuthSession->hmac.size = 0;

    // Read from TPM
    Status = Tpm2NvRead(
        TPM_RH_OWNER,
        USB_HASH_NV_INDEX,
        AuthSession,
        sizeof(COMBINED_STORAGE),
        0, // offset
        OutData);

    if (EFI_ERROR(Status))
    {
        DEBUG((DEBUG_ERROR, "Failed to read combined data from TPM: %r\n", Status));
        goto Cleanup;
    }

    if (OutData->size < sizeof(COMBINED_STORAGE))
    {
        DEBUG((DEBUG_ERROR, "Read data size (%u) smaller than expected (%u)\n",
               OutData->size, sizeof(COMBINED_STORAGE)));
        Status = EFI_BAD_BUFFER_SIZE;
        goto Cleanup;
    }

    // Extract data from buffer
    CombinedData = (COMBINED_STORAGE *)OutData->buffer;
    *Flag = CombinedData->Flag;
    CopyMem(UsbHash, CombinedData->UsbHash, TPM_HASH_SIZE);
    CopyMem(RecoveryHash, CombinedData->RecoveryHash, TPM_HASH_SIZE);

    DEBUG((DEBUG_INFO, "Successfully read combined data Flag=%d\n", *Flag));

Cleanup:
    if (AuthSession)
        FreePool(AuthSession);
    if (OutData)
        FreePool(OutData);
    return Status;
}

// Function to read USB serial from TPM NVRAM
EFI_STATUS
EFIAPI
ReadUsbSerialFromTpm(
    OUT CHAR16 *SerialBuffer,
    IN UINTN BufferSize)
{
    EFI_STATUS Status;
    TPMS_AUTH_COMMAND *AuthSession = NULL;
    TPM2B_MAX_BUFFER *OutData = NULL;
    TPM2B_NV_PUBLIC NvPublic;
    UINTN ReadSize;
    TPM_USB_SERIAL_STORAGE *StoredData;
    TPM2B_NAME NvName;

    if (SerialBuffer == NULL || BufferSize == 0)
    {
        return EFI_INVALID_PARAMETER;
    }

    DEBUG((DEBUG_INFO, "Reading USB serial from TPM at 0x%08X\n", USB_SERIAL_NV_INDEX));

    // Step 1: Read NV index properties
    Status = Tpm2NvReadPublic(USB_SERIAL_NV_INDEX, &NvPublic, &NvName);
    if (EFI_ERROR(Status))
    {
        DEBUG((DEBUG_ERROR, "Failed to read serial NV public: %r\n", Status));
        return Status;
    }

    ReadSize = NvPublic.nvPublic.dataSize;
    if (ReadSize < sizeof(TPM_USB_SERIAL_STORAGE))
    {
        DEBUG((DEBUG_ERROR, "NV space size (%u) smaller than expected (%u)\n",
               ReadSize, sizeof(TPM_USB_SERIAL_STORAGE)));
        return EFI_BAD_BUFFER_SIZE;
    }

    // Allocate TPM structures
    AuthSession = AllocateZeroPool(sizeof(TPMS_AUTH_COMMAND));
    OutData = AllocateZeroPool(sizeof(TPM2B_MAX_BUFFER));
    if (AuthSession == NULL || OutData == NULL)
    {
        Status = EFI_OUT_OF_RESOURCES;
        goto Cleanup;
    }

    // Setup auth session
    AuthSession->sessionHandle = TPM_RS_PW;
    AuthSession->nonce.size = 0;
    *(UINT8 *)&AuthSession->sessionAttributes = 0;
    AuthSession->hmac.size = 0;

    // Read from TPM
    Status = Tpm2NvRead(
        TPM_RH_OWNER,
        USB_SERIAL_NV_INDEX,
        AuthSession,
        sizeof(TPM_USB_SERIAL_STORAGE),
        0, // offset
        OutData);

    if (EFI_ERROR(Status))
    {
        DEBUG((DEBUG_ERROR, "Failed to read serial from TPM: %r\n", Status));
        goto Cleanup;
    }

    if (OutData->size < sizeof(TPM_USB_SERIAL_STORAGE))
    {
        DEBUG((DEBUG_ERROR, "Read data size (%u) smaller than expected (%u)\n",
               OutData->size, sizeof(TPM_USB_SERIAL_STORAGE)));
        Status = EFI_BAD_BUFFER_SIZE;
        goto Cleanup;
    }

    // Extract serial data and convert back to Unicode
    StoredData = (TPM_USB_SERIAL_STORAGE *)OutData->buffer;
    Status = ConvertTpmSerialToUnicode(
        StoredData->SerialNumber,
        SerialBuffer,
        BufferSize);

    if (EFI_ERROR(Status))
    {
        DEBUG((DEBUG_ERROR, "Failed to convert TPM serial to Unicode: %r\n", Status));
        goto Cleanup;
    }

    DEBUG((DEBUG_INFO, "Successfully read USB serial: %s\n", SerialBuffer));

Cleanup:
    if (AuthSession)
        FreePool(AuthSession);
    if (OutData)
        FreePool(OutData);
    return Status;
}

// Function to initialize and setup all USB-related TPM storage
EFI_STATUS
EFIAPI
InitializeUsbTpmStorage(
    VOID)
{
    EFI_STATUS Status;

    // Test TPM connection first
    Status = TestTpmConnection();
    if (EFI_ERROR(Status))
    {
        Print(L"TPM connection test failed: %r\n", Status);
        return Status;
    }

    // Define serial number storage space
    Status = DefineSerialIndex();
    if (EFI_ERROR(Status) && Status != EFI_DEVICE_ERROR)
    {
        Print(L"Failed to define serial NV index: %r\n", Status);
        return Status;
    }

    // Define combined storage space
    Status = DefineCombinedIndex();
    if (EFI_ERROR(Status) && Status != EFI_DEVICE_ERROR)
    {
        Print(L"Failed to define combined NV index: %r\n", Status);
        return Status;
    }

    Print(L"TPM storage initialization completed successfully!\n");
    return EFI_SUCCESS;
}

// Function to compare two USB device hashes
BOOLEAN
CompareUsbHashes(
    IN UINT8 *Hash1,
    IN UINT8 *Hash2)
{
    if (Hash1 == NULL || Hash2 == NULL)
    {
        return FALSE;
    }

    return (CompareMem(Hash1, Hash2, TPM_HASH_SIZE) == 0);
}

// Function to validate USB device against stored hash
EFI_STATUS
EFIAPI
ValidateUsbDevice(
    IN USB_DEVICE *CurrentDevice,
    OUT BOOLEAN *IsValid)
{
    EFI_STATUS Status;
    UINT8 StoredFlag;
    UINT8 StoredUsbHash[TPM_HASH_SIZE];
    UINT8 StoredRecoveryHash[TPM_HASH_SIZE];

    if (CurrentDevice == NULL || IsValid == NULL)
    {
        return EFI_INVALID_PARAMETER;
    }

    *IsValid = FALSE;

    // Read stored data from TPM
    Status = ReadCombinedDataFromTpm(&StoredFlag, StoredUsbHash, StoredRecoveryHash);
    if (EFI_ERROR(Status))
    {
        DEBUG((DEBUG_ERROR, "Failed to read stored USB hash: %r\n", Status));
        return Status;
    }

    // Compare current device hash with stored hash
    if (CompareUsbHashes(CurrentDevice->Hash, StoredUsbHash))
    {
        *IsValid = TRUE;
        DEBUG((DEBUG_INFO, "USB device validation successful\n"));
    }
    else
    {
        DEBUG((DEBUG_WARN, "USB device validation failed - hash mismatch\n"));
    }

    return EFI_SUCCESS;
}

// Function to display hash in readable format
VOID DisplayHash(
    IN CHAR16 *Label,
    IN UINT8 *Hash)
{
    if (Label == NULL || Hash == NULL)
    {
        return;
    }

    Print(L"%s: ", Label);
    for (UINTN i = 0; i < TPM_HASH_SIZE; i++)
    {
        Print(L"%02X", Hash[i]);
        if ((i + 1) % 16 == 0 && i < TPM_HASH_SIZE - 1)
        {
            Print(L"\n%*s", StrLen(Label) + 2, L"");
        }
    }
    Print(L"\n");
}

EFI_STATUS
EFIAPI
Tpm2NvUndefineSpaceC(
    IN TPMI_RH_PROVISION AuthHandle,
    IN TPMI_RH_NV_INDEX NvIndex,
    IN TPMS_AUTH_COMMAND *AuthSession)
{
    EFI_STATUS Status;
    TPM2_COMMAND_HEADER CmdHeader;        // Header structure for TPM commands
    UINT8 CmdBuffer[512];                 // Buffer to hold the complete command
    UINT8 RespBuffer[256];                // Buffer to hold the TPM response
    UINT32 CmdSize = 0;                   // Current size of command being built
    UINT32 RespSize = sizeof(RespBuffer); // Size of response buffer
    UINT32 AuthSize;                      // Size of the authorization area

    // Build the command header
    // TPM_ST_SESSIONS indicates this command includes authorization sessions
    CmdHeader.tag = SwapBytes16(TPM_ST_SESSIONS);
    // The specific command code for NV_UndefineSpace
    CmdHeader.commandCode = SwapBytes32(TPM_CC_NV_UndefineSpace);

    // Copy the header to the beginning of our command buffer
    CopyMem(CmdBuffer, &CmdHeader, sizeof(CmdHeader));
    CmdSize = sizeof(CmdHeader);

    // Add the authorization handle (who is authorizing the deletion)
    *(UINT32 *)(CmdBuffer + CmdSize) = SwapBytes32(AuthHandle);
    CmdSize += sizeof(UINT32);

    // Add the NV index to be undefined (deleted)
    *(UINT32 *)(CmdBuffer + CmdSize) = SwapBytes32(NvIndex);
    CmdSize += sizeof(UINT32);

    // Reserve space for the authorization size
    // We'll fill this in after building the authorization area
    UINT32 AuthSizeOffset = CmdSize;
    CmdSize += sizeof(UINT32);

    // Mark the start of the authorization session data
    UINT32 AuthStart = CmdSize;

    // Add the session handle (type of authorization)
    *(UINT32 *)(CmdBuffer + CmdSize) = SwapBytes32(AuthSession->sessionHandle);
    CmdSize += sizeof(UINT32);

    // Add nonce size (typically 0 for password sessions)
    *(UINT16 *)(CmdBuffer + CmdSize) = SwapBytes16(AuthSession->nonce.size);
    CmdSize += sizeof(UINT16);

    // Add nonce buffer if present
    if (AuthSession->nonce.size > 0)
    {
        CopyMem(CmdBuffer + CmdSize, AuthSession->nonce.buffer, AuthSession->nonce.size);
        CmdSize += AuthSession->nonce.size;
    }

    // Add session attributes (control flags for the session)
    // Each bit represents a different attribute
    CmdBuffer[CmdSize] =
        (AuthSession->sessionAttributes.continueSession ? 0x01 : 0) |
        (AuthSession->sessionAttributes.auditExclusive ? 0x02 : 0) |
        (AuthSession->sessionAttributes.auditReset ? 0x04 : 0) |
        (AuthSession->sessionAttributes.decrypt ? 0x20 : 0) |
        (AuthSession->sessionAttributes.encrypt ? 0x40 : 0) |
        (AuthSession->sessionAttributes.audit ? 0x80 : 0);
    CmdSize += 1;

    // Add HMAC/password size
    *(UINT16 *)(CmdBuffer + CmdSize) = SwapBytes16(AuthSession->hmac.size);
    CmdSize += sizeof(UINT16);

    // Add HMAC/password if present
    if (AuthSession->hmac.size > 0)
    {
        CopyMem(CmdBuffer + CmdSize, AuthSession->hmac.buffer, AuthSession->hmac.size);
        CmdSize += AuthSession->hmac.size;
    }

    // Calculate and set the authorization area size
    AuthSize = CmdSize - AuthStart;
    *(UINT32 *)(CmdBuffer + AuthSizeOffset) = SwapBytes32(AuthSize);

    // Update the total command size in the header
    *(UINT32 *)(CmdBuffer + 2) = SwapBytes32(CmdSize);

    // Send the command to the TPM
    Status = Tpm2SubmitCommandC(CmdSize, CmdBuffer, &RespSize, RespBuffer);
    if (EFI_ERROR(Status))
    {
        DEBUG((DEBUG_ERROR, "Tpm2NvUndefineSpace: Command submission failed: %r\n", Status));
        return Status;
    }

    // Check the TPM response code
    TPM2_RESPONSE_HEADER *RespHeader = (TPM2_RESPONSE_HEADER *)RespBuffer;
    TPM_RC ResponseCode = SwapBytes32(RespHeader->responseCode);

    if (ResponseCode != TPM_RC_SUCCESS)
    {
        DEBUG((DEBUG_ERROR, "Tpm2NvUndefineSpace: TPM returned error: 0x%x\n", ResponseCode));
        return EFI_DEVICE_ERROR;
    }

    return EFI_SUCCESS;
}

/**
 * UndefineNvSpace - Wrapper function to undefine (delete) our NV space
 *
 * This function sets up the authorization and calls Tpm2NvUndefineSpace to
 * delete the NV space at index 0x01510000.
 *
 * @return EFI_STATUS - Result of the operation
 */
EFI_STATUS
EFIAPI
UndefineNvSpace(
    VOID)
{
    EFI_STATUS Status;
    TPMI_RH_PROVISION AuthHandle;   // Authentication handle
    TPMS_AUTH_COMMAND *AuthSession; // Authorization session structure

    // Allocate memory for the authorization session
    AuthSession = (TPMS_AUTH_COMMAND *)AllocateZeroPool(sizeof(TPMS_AUTH_COMMAND));
    if (AuthSession == NULL)
    {
        Print(L"Failed to allocate memory\n");
        return EFI_OUT_OF_RESOURCES;
    }

    // Set up the authorization session similar to read/write operations
    // This ensures consistent authorization across all operations
    AuthSession->sessionHandle = TPM_RS_PW;
    AuthSession->nonce.size = 0;
    AuthSession->sessionAttributes.continueSession = 0;
    AuthSession->sessionAttributes.auditExclusive = 0;
    AuthSession->sessionAttributes.auditReset = 0;
    AuthSession->sessionAttributes.decrypt = 0;
    AuthSession->sessionAttributes.encrypt = 0;
    AuthSession->sessionAttributes.audit = 0;
    AuthSession->hmac.size = 0;

    // Use TPM_RH_OWNER as auth handle - this must match what was used when defining the space
    AuthHandle = TPM_RH_OWNER;

    Print(L"\nAttempting to undefine NV index 0x01510000...\n");
    DEBUG((DEBUG_INFO, "\nAttempting to undefine NV index 0x01510000...\n"));

    // Call the function to undefine/delete the NV space
    Status = Tpm2NvUndefineSpaceC(AuthHandle, 0x01510000, AuthSession);
    if (EFI_ERROR(Status))
    {
        Print(L"Tpm2NvUndefineSpace failed: %r\n", Status);
    }
    else
    {
        Print(L"Successfully undefined NV index 0x01510000\n");
        DEBUG((DEBUG_INFO, "Successfully undefined NV index 0x01510000\n"));
    }

    // Clean up resources
    FreePool(AuthSession);

    return Status;
}

// **************************************************RandomNumber
// Func************************************
EFI_STATUS
EFIAPI
RngTestEntryPoint(CHAR16 *FormattedRandom, UINTN MaxSize)
{
    EFI_TCG2_PROTOCOL *Tcg2Protocol;
    EFI_STATUS Status;

    Status =
        gBS->LocateProtocol(&gEfiTcg2ProtocolGuid, NULL, (VOID **)&Tcg2Protocol);
    if (EFI_ERROR(Status))
    {
        // Print(L"LocateProtocol failed: %r\n", Status);
        DEBUG((DEBUG_INFO, "LocateProtocol failed: %r\n", Status));
        return Status;
    }
    DEBUG((DEBUG_INFO,
           "Initiating the Random Number Generator Function........\r\n"));
    DEBUG((DEBUG_INFO, "\r\n"));

    TPM2_GET_RANDOM_COMMAND CmdBuffer;
    UINT32 CmdBufferSize;
    TPM2_GET_RANDOM_RESPONSE RecvBuffer;
    UINT32 RecvBufferSize;

    CmdBuffer.Header.tag = SwapBytes16(TPM_ST_NO_SESSIONS);
    CmdBuffer.Header.commandCode = SwapBytes32(TPM_CC_GetRandom);
    CmdBuffer.bytesRequested = SwapBytes16(10);
    CmdBufferSize = sizeof(CmdBuffer.Header) + sizeof(CmdBuffer.bytesRequested);
    CmdBuffer.Header.paramSize = SwapBytes32(CmdBufferSize);

    // send
    RecvBufferSize = sizeof(RecvBuffer);
    Status = Tcg2Protocol->SubmitCommand(Tcg2Protocol, CmdBufferSize,
                                         (UINT8 *)&CmdBuffer, RecvBufferSize,
                                         (UINT8 *)&RecvBuffer);

    if (Status == EFI_SUCCESS)
    {
        DEBUG((DEBUG_INFO, "SubmitCommand Success!\r\n"));
    }
    else
    {
        DEBUG((DEBUG_INFO,
               "stats: 0x%x (EFI_DEVICE_ERROR:0x%x, EFI_INVALID_PARAMETER:0x%x, "
               "EFI_BUFFER_TOO_SMALL:0x%x)\r\n",
               Status, EFI_DEVICE_ERROR, EFI_INVALID_PARAMETER,
               EFI_BUFFER_TOO_SMALL));
        Print(L"stats: 0x%x (EFI_DEVICE_ERROR:0x%x, EFI_INVALID_PARAMETER:0x%x, "
              L"EFI_BUFFER_TOO_SMALL:0x%x)\r\n",
              Status, EFI_DEVICE_ERROR, EFI_INVALID_PARAMETER,
              EFI_BUFFER_TOO_SMALL);
    }

    // show result
    UINT32 res = SwapBytes32(RecvBuffer.Header.responseCode);
    if (res != TPM_RC_SUCCESS)
    {
        DEBUG((DEBUG_ERROR, "TPM command failed: 0x08x\n", res));
        return EFI_DEVICE_ERROR;
    }
    DEBUG((DEBUG_INFO, "ResponseCode is %d\r\n", res));
    // CHAR16 FormattedRandom[32];
    UINTN j = 0, k = 0;

    for (UINTN i = 0; i < 10; i++)
    { // 10 bytes = 20 hex digits
        UnicodeSPrint(&FormattedRandom[j], 5 * sizeof(CHAR16), L"%02X",
                      RecvBuffer.randomBytes.buffer[i]);
        j += 2;
        k++;
        // Insert dash every 4 hex digits (i.e., every 2 bytes), but not after the
        // last group
        if ((k % 2 == 0) && (k != 10))
        {
            FormattedRandom[j++] = L'-';
        }
    }
    FormattedRandom[j] = L'\0';

    DEBUG((DEBUG_INFO, "........................................................."
                       "................\r\n"));
    DEBUG((DEBUG_INFO, "Generated TPM Random Number: %s\n", FormattedRandom));
    // Print(L"\n\nPlease save this number for Recovery Purpose: %s\n",
    // FormattedRandom);
    DEBUG((DEBUG_INFO, "........................................................."
                       "................\r\n"));
    return 0;
}

// **************************************************TPM Hash
// Func*****************************************
EFI_STATUS
Tpm2HashUsbDeviceInfo(
    IN UINT16 Vid,
    IN UINT16 Pid,
    IN CHAR16 *SerialNumber,
    OUT UINT8 *Digest,  // Output: SHA-256 hash
    IN UINTN DigestSize // Must be at least 32 bytes
)
{
    EFI_STATUS Status;
    TPMI_DH_OBJECT SequenceHandle;
    TPM2B_MAX_BUFFER HashBuffer;
    TPM2B_DIGEST Result;
    // TPMT_TK_HASHCHECK      Validation;
    UINT8 *DataToHash;
    UINTN DataSize;
    CHAR8 AsciiSerial[64];

    if (Digest == NULL || SerialNumber == NULL || DigestSize < TPM_HASH_SIZE)
    {
        return EFI_INVALID_PARAMETER;
    }

    UnicodeStrToAsciiStrS(SerialNumber, AsciiSerial, sizeof(AsciiSerial));

    // Combine VID, PID, and SerialNumber into a single buffer
    UINTN SerialLen = AsciiStrLen(AsciiSerial);
    // DataSize = sizeof(Vid) + sizeof(Pid) + (SerialLen * sizeof(CHAR16));
    DataSize = sizeof(Vid) + sizeof(Pid) + SerialLen;
    DataToHash = AllocateZeroPool(DataSize);
    if (DataToHash == NULL)
    {
        return EFI_OUT_OF_RESOURCES;
    }

    CopyMem(DataToHash, &Vid, sizeof(Vid));
    CopyMem(DataToHash + sizeof(Vid), &Pid, sizeof(Pid));
    // CopyMem(DataToHash + sizeof(Vid) + sizeof(Pid), SerialNumber, SerialLen *
    // sizeof(CHAR16));
    CopyMem(DataToHash + sizeof(Vid) + sizeof(Pid), AsciiSerial, SerialLen);

    // Start hash sequence
    Status = Tpm2HashSequenceStart(TPM_HASH_ALGO, &SequenceHandle);
    if (EFI_ERROR(Status))
    {
        DEBUG((DEBUG_ERROR, "Tpm2HashSequenceStart failed: %r\n", Status));
        FreePool(DataToHash);
        return Status;
    }

    // TPM expects updates in chunks <= MAX_BUFFER
    UINTN Remaining = DataSize;
    UINT8 *Ptr = DataToHash;

    while (Remaining > 0)
    {
        UINTN ChunkSize = (Remaining > sizeof(HashBuffer.buffer))
                              ? sizeof(HashBuffer.buffer)
                              : Remaining;

        HashBuffer.size = (UINT16)ChunkSize;
        CopyMem(HashBuffer.buffer, Ptr, ChunkSize);

        Status = Tpm2SequenceUpdate(SequenceHandle, &HashBuffer);
        if (EFI_ERROR(Status))
        {
            DEBUG((DEBUG_ERROR, "Tpm2SequenceUpdate failed: %r\n", Status));
            Tpm2FlushContext(SequenceHandle);
            FreePool(DataToHash);
            return Status;
        }

        Ptr += ChunkSize;
        Remaining -= ChunkSize;
    }

    // Complete the hash sequence
    ZeroMem(&HashBuffer, sizeof(HashBuffer)); // Empty buffer for completion
    Status = Tpm2SequenceComplete(SequenceHandle, &HashBuffer, &Result);

    if (EFI_ERROR(Status))
    {
        DEBUG((DEBUG_ERROR, "Tpm2SequenceComplete failed: %r\n", Status));
        FreePool(DataToHash);
        return Status;
    }

    // Copy result
    CopyMem(Digest, Result.buffer, 32);
    FreePool(DataToHash);
    return EFI_SUCCESS;
}

VOID DisplayUsbDeviceInfo(
    UINTN DeviceIndex,
    USB_DEVICE *DeviceInfo)
{
    Print(L"\n-- USB Device %d details and generated hash --\n", DeviceIndex + 1);
    Print(L"VID: %04X\n", DeviceInfo->Vid);
    Print(L"PID: %04X\n", DeviceInfo->Pid);
    Print(L"Serial: %s\n", DeviceInfo->SerialNumber);

    Print(L"SHA-256 Hash: ");
    for (UINTN i = 0; i < 32; i++)
    {
        Print(L"%02X", DeviceInfo->Hash[i]);
        if ((i + 1) % 16 == 0)
            Print(L"\n              ");
    }
    Print(L"\n");
}

// ************************************************TPM Hash Random NUmber
// Func*****************************
EFI_STATUS
Tpm2HashRandomNum(
    IN UINT64 RecoveryCode, // Typically a parsed 18-digit number
    OUT UINT8 *Digest,      // Output: SHA-256 hash
    IN UINTN DigestSize     // Must be at least 32 bytes
)
{
    EFI_STATUS Status;
    TPMI_DH_OBJECT SequenceHandle;
    TPM2B_MAX_BUFFER HashBuffer;
    TPM2B_DIGEST Result;
    UINT8 *DataToHash;
    UINTN DataSize;

    if (Digest == NULL || DigestSize < TPM_HASH_SIZE)
    {
        return EFI_INVALID_PARAMETER;
    }

    // Treat the UINT64 RecoveryCode as raw binary data
    DataSize = sizeof(RecoveryCode);
    DataToHash = AllocateZeroPool(DataSize);
    if (DataToHash == NULL)
    {
        return EFI_OUT_OF_RESOURCES;
    }
    CopyMem(DataToHash, &RecoveryCode, DataSize);

    // Start TPM hash sequence
    Status = Tpm2HashSequenceStart(TPM_HASH_ALGO, &SequenceHandle);
    if (EFI_ERROR(Status))
    {
        DEBUG((DEBUG_ERROR, "Tpm2HashSequenceStart failed: %r\n", Status));
        FreePool(DataToHash);
        return Status;
    }

    // TPM expects input in chunks <= MAX_BUFFER
    UINTN Remaining = DataSize;
    UINT8 *Ptr = DataToHash;

    while (Remaining > 0)
    {
        UINTN ChunkSize = (Remaining > sizeof(HashBuffer.buffer))
                              ? sizeof(HashBuffer.buffer)
                              : Remaining;

        HashBuffer.size = (UINT16)ChunkSize;
        CopyMem(HashBuffer.buffer, Ptr, ChunkSize);

        Status = Tpm2SequenceUpdate(SequenceHandle, &HashBuffer);
        if (EFI_ERROR(Status))
        {
            DEBUG((DEBUG_ERROR, "Tpm2SequenceUpdate failed: %r\n", Status));
            Tpm2FlushContext(SequenceHandle);
            FreePool(DataToHash);
            return Status;
        }

        Ptr += ChunkSize;
        Remaining -= ChunkSize;
    }

    // Complete the hash operation
    ZeroMem(&HashBuffer, sizeof(HashBuffer)); // No final data chunk
    Status = Tpm2SequenceComplete(SequenceHandle, &HashBuffer, &Result);
    if (EFI_ERROR(Status))
    {
        DEBUG((DEBUG_ERROR, "Tpm2SequenceComplete failed: %r\n", Status));
        FreePool(DataToHash);
        return Status;
    }

    // Copy digest to output
    CopyMem(Digest, Result.buffer,
            (Result.size < DigestSize) ? Result.size : DigestSize);
    FreePool(DataToHash);
    return EFI_SUCCESS;
}

//****************************************************GetUsbDetails
// FUnc*******************************
/**
 * Retrieves details about a USB device and formats them into a string.
 */
EFI_STATUS
GetUsbDeviceDetails(
    EFI_HANDLE UsbHandle,
    EFI_USB_IO_PROTOCOL *UsbIo,
    CHAR8 *UsbInfo,
    UINTN UsbInfoSize,
    UINT16 *VidOut,          // Added for VID output
    UINT16 *PidOut,          // Added for PID output
    CHAR16 *SerialNumberOut, // Added for serial number output
    UINTN SerialNumberSize   // Size of serial number buffer
)
{
    EFI_STATUS Status;
    EFI_USB_DEVICE_DESCRIPTOR DeviceDescriptor;
    EFI_DEVICE_PATH_PROTOCOL *DevicePath;
    EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *DevicePathToText;
    CHAR16 *DevicePathText = NULL;

    // Retrieve the USB device descriptor
    Status = UsbIo->UsbGetDeviceDescriptor(UsbIo, &DeviceDescriptor);
    if (EFI_ERROR(Status))
    {
        DEBUG((DEBUG_ERROR, "Error: Failed to get USB Device Descriptor\n"));
        return Status;
    }

    // Extract Vendor ID, Product ID, and Device Number
    UINT16 Vid = DeviceDescriptor.IdVendor;
    UINT16 Pid = DeviceDescriptor.IdProduct;
    UINT16 DeviceNumber = DeviceDescriptor.BcdDevice;

    // Check if VID/PID are invalid and retry
    if (Vid == 0xFFFF || Pid == 0xFFFF)
    {
        DEBUG((DEBUG_WARN, "Invalid VID/PID detected. Retrying after delay...\n"));
        gBS->Stall(1000000);
        Status = UsbIo->UsbGetDeviceDescriptor(UsbIo, &DeviceDescriptor);
        if (!EFI_ERROR(Status))
        {
            Vid = DeviceDescriptor.IdVendor;
            Pid = DeviceDescriptor.IdProduct;
        }
    }

    DEBUG((DEBUG_INFO, "Final USB VID: %04X, PID: %04X\n", Vid, Pid));

    // Retrieve serial number
    ZeroMem(SerialNumberOut, SerialNumberSize);
    if (DeviceDescriptor.StrSerialNumber != 0)
    {
        CHAR16 *SerialBuffer = NULL;
        Status = UsbIo->UsbGetStringDescriptor(
            UsbIo, 0x0409, DeviceDescriptor.StrSerialNumber, &SerialBuffer);
        if (EFI_ERROR(Status) || SerialBuffer == NULL)
        {
            DEBUG(
                (DEBUG_WARN, "Warning: Failed to get serial number - %r\n", Status));
            StrCpyS(SerialNumberOut, SerialNumberSize / sizeof(CHAR16), L"NoSerial");
        }
        else
        {
            UINTN SerialLen = StrLen(SerialBuffer);
            if (SerialLen > 0 && SerialLen < (SerialNumberSize / sizeof(CHAR16)))
            {
                StrCpyS(SerialNumberOut, SerialNumberSize / sizeof(CHAR16),
                        SerialBuffer);
            }
            else
            {
                DEBUG((DEBUG_WARN, "Warning: Invalid serial number length: %d\n",
                       SerialLen));
                StrCpyS(SerialNumberOut, SerialNumberSize / sizeof(CHAR16),
                        L"NoSerial");
            }
            gBS->FreePool(SerialBuffer);
        }
    }
    else
    {
        StrCpyS(SerialNumberOut, SerialNumberSize / sizeof(CHAR16), L"NoSerial");
    }

    // Output VID, PID, and serial number
    *VidOut = Vid;
    *PidOut = Pid;

    // Retrieve the device path
    Status = gBS->HandleProtocol(UsbHandle, &gEfiDevicePathProtocolGuid,
                                 (VOID **)&DevicePath);
    if (EFI_ERROR(Status))
    {
        DEBUG((DEBUG_ERROR, "Error: Failed to get Device Path\n"));
        return Status;
    }

    Status = gBS->LocateProtocol(&gEfiDevicePathToTextProtocolGuid, NULL,
                                 (VOID **)&DevicePathToText);
    if (EFI_ERROR(Status))
    {
        DEBUG((DEBUG_ERROR, "Error: Failed to locate DevicePathToText protocol\n"));
        return Status;
    }

    DevicePathText =
        DevicePathToText->ConvertDevicePathToText(DevicePath, TRUE, TRUE);
    if (DevicePathText == NULL)
    {
        DevicePathText = AllocateZeroPool(20 * sizeof(CHAR16));
        StrCpyS(DevicePathText, 20, L"Unknown");
    }

    CHAR8 DevicePathAscii[512];
    UnicodeStrToAsciiStrS(DevicePathText, DevicePathAscii,
                          sizeof(DevicePathAscii));

    // Format USB details into the output buffer
    AsciiSPrint(UsbInfo, UsbInfoSize, "%04X--%04X--%04X--%a", Vid, Pid,
                DeviceNumber, DevicePathAscii);

    FreePool(DevicePathText);
    return EFI_SUCCESS;
}

//**************************************************SelectUsbDev
// Func************************************
/**
 * Displays all USB devices and prompts user to select one.
 * Returns the index of the selected device or -1 if invalid.
 */
INTN SelectUsbDevice(EFI_HANDLE *HandleBuffer, UINTN HandleCount)
{
    EFI_STATUS Status;
    EFI_USB_IO_PROTOCOL *UsbIo;
    UINTN i;
    CHAR16 Input[10];
    UINTN SelectedIndex;

    Print(L"\nAvailable USB Devices:\n");
    DEBUG((DEBUG_INFO, "Available USB Devices : \n"));
    for (i = 0; i < HandleCount; i++)
    {
        Status = gBS->HandleProtocol(HandleBuffer[i], &gEfiUsbIoProtocolGuid,
                                     (VOID **)&UsbIo);
        if (EFI_ERROR(Status))
        {
            DEBUG((DEBUG_ERROR, "Error: Failed to get USB protocol for device %d\n",
                   i));
            continue;
        }

        UINT16 Vid, Pid;
        CHAR16 SerialNumber[128];
        CHAR8 UsbInfo[512];

        Status =
            GetUsbDeviceDetails(HandleBuffer[i], UsbIo, UsbInfo, sizeof(UsbInfo),
                                &Vid, &Pid, SerialNumber, sizeof(SerialNumber));
        if (EFI_ERROR(Status))
            continue;

        Print(L"[%d] VID: %04X\n    PID: %04X\n    Serial: %s\n", i + 1, Vid, Pid,
              SerialNumber);
        DEBUG((DEBUG_INFO, "[%d] VID: %04X\n    PID: %04X\n    Serial: %s\n", i + 1,
               Vid, Pid, SerialNumber));
    }

    Print(
        L"\nPlease enter the number of the USB device for registration (1-%d): _",
        HandleCount);
    DEBUG((DEBUG_INFO,
           "\nPlease enter the number of the USB device for registration  (1-%d) "
           ": _",
           HandleCount));
    Input[0] = 0;
    Status = gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, NULL);
    if (!EFI_ERROR(Status))
    {
        EFI_INPUT_KEY Key;
        gST->ConIn->ReadKeyStroke(gST->ConIn, &Key);
        if (Key.UnicodeChar >= L'1' && Key.UnicodeChar <= L'9')
        {
            UnicodeSPrint(Input, sizeof(Input), L"%d", Key.UnicodeChar - L'0');
            SelectedIndex = StrDecimalToUintn(Input);
            if (SelectedIndex >= 1 && SelectedIndex <= HandleCount)
            {
                return (INTN)(SelectedIndex - 1);
            }
        }
    }

    Print(L"Invalid selection.\n");
    DEBUG((DEBUG_INFO, "Invalid Selection.\n"));
    return -1;
}

EFI_STATUS
ReadLine(OUT CHAR16 *Buffer, IN UINTN ExpectedLen)
{
    UINTN Index = 0;
    EFI_INPUT_KEY Key;
    EFI_STATUS Status;

    DEBUG(
        (DEBUG_INFO, "Enter exactly %u alphanumeric characters: ", ExpectedLen));

    while (TRUE)
    {
        Status = gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, NULL);
        if (EFI_ERROR(Status))
        {
            return Status;
        }

        Status = gST->ConIn->ReadKeyStroke(gST->ConIn, &Key);
        if (EFI_ERROR(Status))
        {
            continue;
        }

        if (Key.UnicodeChar == CHAR_CARRIAGE_RETURN)
        {
            if (Index == ExpectedLen)
            {
                break; // Accept only if input is exactly ExpectedLen
            }
            else
            {
                Print(L"\nInput must be exactly %u characters. Try again: ",
                      ExpectedLen);
                Index = 0;
                continue;
            }
        }
        else if (Key.UnicodeChar == CHAR_BACKSPACE && Index > 0)
        {
            Index--;
            Print(L"\b \b");
        }
        else if ((Key.UnicodeChar >= L'0' && Key.UnicodeChar <= L'9') ||
                 (Key.UnicodeChar >= L'A' && Key.UnicodeChar <= L'Z') ||
                 (Key.UnicodeChar >= L'a' && Key.UnicodeChar <= L'z') ||
                 (Key.UnicodeChar == L'-'))
        {
            if (Index < ExpectedLen)
            {
                Buffer[Index++] = Key.UnicodeChar;
                Print(L"%c", Key.UnicodeChar);
            }
        }
        // Ignore non-alphanumeric characters silently
    }

    Buffer[Index] = L'\0';
    Print(L"\n");

    return EFI_SUCCESS;
}

EFI_STATUS
Tpm2HashBuffer(IN UINT8 *Buffer, IN UINTN BufferSize, OUT UINT8 *Digest,
               IN UINTN DigestSize)
{
    if (DigestSize < SHA256_DIGEST_SIZE)
    {
        return EFI_BUFFER_TOO_SMALL;
    }

    if (!Sha256HashAll(Buffer, BufferSize, Digest))
    {
        return EFI_DEVICE_ERROR;
    }

    return EFI_SUCCESS;
}

//*************************************************Recovery System
// Func***********************************************
EFI_STATUS
EFIAPI
RecoverySystem(VOID)
{
    EFI_STATUS Status;
    CHAR16 InputBuffer[25];
    // UINT64            RandomNum;
    //RND_HASH_INFO StoredDev;
    //UINTN Size = sizeof(RND_HASH_INFO);
    UINT8 InputDigest[32];
 //   UINT16 Vid = 0x0000;
 //   UINT16 Pid = 0x0000;
   // CHAR16 SerialNumber[128] = L"00000000000"; // Max serial number length
    //UINT8 Flag = 0;                            // 0 = not registered, 1 = registered
    USB_DEVICE NewDev;

   StrCpyS(NewDev.SerialNumber, sizeof(NewDev.SerialNumber) / sizeof(CHAR16), L"0000000000");

      


    Print(L"\nInitializing the Recovery Mode....\n");
    DEBUG((DEBUG_INFO, "Initializing the Recovery Mode....\n"));

    UINT8 AttemptsLeft = 3;
BOOLEAN Verified = FALSE;

while (AttemptsLeft > 0)
{
    Print(L"Enter your 20-digit recovery code (in format xxxx-xxxx): \n");
    DEBUG((DEBUG_INFO, "\nRecovery Mode: Enter your 20-digit recovery code (in format xxxx-xxxx): \n"));

    Status = ReadLine(InputBuffer, 24);
    if (EFI_ERROR(Status))
    {
        Print(L"Failed to read input.\n");
        AttemptsLeft--;
        continue;
    }

    Print(L"You have entered: %s\n", InputBuffer);
    DEBUG((DEBUG_INFO, "User has entered: %s\n", InputBuffer));

    UINTN InputLenBytes = StrLen(InputBuffer) * sizeof(CHAR16);
    Status = Tpm2HashBuffer((UINT8 *)InputBuffer, InputLenBytes, InputDigest, 32);

    if (EFI_ERROR(Status))
    {
        Print(L"Failed to hash input recovery code.\n");
        AttemptsLeft--;
        continue;
    }

    DEBUG((DEBUG_INFO, "Computed Hash of Recovery Code Input: "));
    for (UINTN i = 0; i < 32; i++)
    {
        DEBUG((DEBUG_INFO, "%02x", InputDigest[i]));
    }
    DEBUG((DEBUG_INFO, "\n"));

    // Fetch stored digest
    //Size = sizeof(RND_HASH_INFO);
    
    //Status = gRT->GetVariable(L"RandomHashNumb", &gRandomHashNvramGuid, NULL, &Size, &StoredDev);
    ReadCombinedDataFromTpm(&NewDev.Flag, NewDev.Hash, NewDev.RecoveryHash);
    if (EFI_ERROR(Status))
    {
        Print(L"Failed to load stored recovery hash. Recovery unavailable.\n");
        DEBUG((DEBUG_INFO, "Failed to load stored recovery hash. Status: %r\n", Status));
        return Status;
    }

    DEBUG((DEBUG_INFO, "Stored Hash of Random Number: "));
    for (UINTN i = 0; i < 32; i++)
    {
        DEBUG((DEBUG_INFO, "%02x", NewDev.RecoveryHash));
    }
    DEBUG((DEBUG_INFO, "\n"));

    BOOLEAN Match = TRUE;
    for (UINTN i = 0; i < 32; i++)
    {
        if (InputDigest[i] != NewDev.RecoveryHash[i])
        {
            DEBUG((DEBUG_INFO, "Mismatch at byte %u: InputDigest=%02x, StoredDigest=%02x\n", i, InputDigest[i], NewDev.RecoveryHash[i]));
            Match = FALSE;
        }
    }

    if (Match)
    {
        Verified = TRUE;
        break;
    }
    else
    {
        AttemptsLeft--;
        Print(L"\nInvalid recovery code. Attempts remaining: %u\n", AttemptsLeft);
        DEBUG((DEBUG_INFO, "Invalid recovery code. Attempts remaining: %u\n", AttemptsLeft));
    }
}

// If verified, unregister device
if (Verified)
{
    Print(L"Recovery code verified successfully.\nUnregistering the USB Device...\n");
    DEBUG((DEBUG_INFO, "Hash matched successfully. Proceeding with unregistration.\n"));
/**
    NewestDev.Vid = Vid;
    NewestDev.Pid = Pid;
    StrCpyS(NewestDev.SerialNumber,
            sizeof(NewestDev.SerialNumber) / sizeof(CHAR16), SerialNumber);
    NewestDev.Flag = Flag;

    Status = gRT->SetVariable(L"DxeHashUsbDevice", &gDxeHashNvramGuid,
                              NVRAM_VARIABLE_ATTRIBUTES,
                              sizeof(USB_DEVICE_INFO), &NewestDev);

    if (EFI_ERROR(Status))
    {
        Print(L"Failed to store device info in NVRAM: %r\n", Status);
        DEBUG((DEBUG_INFO, "Failed to store device info in NVRAM: %r\n", Status));
    }
    else
    {
        DEBUG((DEBUG_INFO, "Device info cleared successfully.\n"));
    }
**/
//   NewDev.Flag = 0;
    //Status = StoreCombinedDataInTpm(NewDev.Flag, NewDev.Hash, NewDev.RecoveryHash);
     //if(!EFI_ERROR(Status)){
     // DEBUG((DEBUG_INFO,"Flag set to 0\n"));
  //  } else {
     //   DEBUG((DEBUG_INFO,"flag doesnt set: %r\n", Status));
    //  }
    Status = StoreUsbSerialInTpm(NewDev.SerialNumber);
    if(!EFI_ERROR(Status)){
      DEBUG((DEBUG_INFO,"Serial - 000..\n"));
    }
    
    USB_DEVICE ClearDevice = {0};
        ClearDevice.Flag = 0;  // Set flag to 0
        StrCpyS(ClearDevice.SerialNumber, sizeof(ClearDevice.SerialNumber) / sizeof(CHAR16), L"0000000000");
        
        Status = gRT->SetVariable(
            L"DxeHashUsbDevice", 
            &gDxeHashNvramGuid,
            NVRAM_VARIABLE_ATTRIBUTES,
            sizeof(USB_DEVICE),  
            &ClearDevice
        );
        //ReadCombinedDataFromTpm(&NewDev.Flag, NewDev.Hash, NewDev.RecoveryHash);
        
    Print(L"\nPress ENTER to reboot the system _\n");
    EFI_INPUT_KEY Key;
    while (TRUE)
    {
        gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, NULL);
        gST->ConIn->ReadKeyStroke(gST->ConIn, &Key);
        if (Key.UnicodeChar == CHAR_CARRIAGE_RETURN)
        {
            Print(L"Rebooting the System now...\n");
            DEBUG((DEBUG_INFO, "Rebooting the System now....\n"));
            gBS->Stall(1000000);
            gRT->ResetSystem(EfiResetWarm, EFI_SUCCESS, 0, NULL);
            break;
        }
    }
    return EFI_SUCCESS;
}
else
{
    Print(L"No attempts remaining. System remains locked.\n");
    DEBUG((DEBUG_INFO, "No attempts remaining. System remains locked.\n"));
    gBS->Stall(2000000);
    gRT->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);
    return EFI_SECURITY_VIOLATION;
}
}


//*********************************************************Dxe Entry Point
// Func*********************************************
/**
 * Entry point for the BDS phase USB enumeration driver.
 */
EFI_STATUS
EFIAPI
DxeUsbEntryPoint(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable)
{
    EFI_STATUS Status;
    EFI_USB_IO_PROTOCOL *UsbIo;
    EFI_HANDLE *HandleBuffer = NULL;
    UINTN HandleCount = 0;
    USB_DEVICE StoredDevice = {0};  // Single structure to hold all stored device data
    USB_DEVICE SavedDev = {0};
    BOOLEAN DeviceRegistered = FALSE;
    StoredDevice.Flag = 0;
    
    Print(L"   ╔════════════════════════════════════╗\r\n");
    Print(L"   ║  ❤  Welcome to CDAC...              ║\r\n");
    Print(L"   ╚════════════════════════════════════╝\r\n");

    DEBUG((DEBUG_INFO, "=== USB AUTHENTICATION DEBUG START ===\n"));
    
    // USB stack initialization
    DEBUG((DEBUG_INFO, "Disconnecting USB controllers...\n"));
    gBS->DisconnectController(ImageHandle, NULL, NULL);
    gBS->Stall(1000000);
    
    DEBUG((DEBUG_INFO, "Reconnecting USB controllers...\n"));
    gBS->ConnectController(ImageHandle, NULL, NULL, TRUE);
    gBS->Stall(1000000);

    // Ensure USB stack is ready
    Status = gBS->LocateProtocol(&gEfiUsbIoProtocolGuid, NULL, (VOID **)&UsbIo);
    if (EFI_ERROR(Status))
    {
        DEBUG((DEBUG_ERROR, "USB stack not initialized yet. Waiting...\n"));
        gBS->Stall(1000000);
        Status = gBS->LocateProtocol(&gEfiUsbIoProtocolGuid, NULL, (VOID **)&UsbIo);
        if (EFI_ERROR(Status))
        {
            DEBUG((DEBUG_ERROR, "USB stack still not ready. Exiting.\n"));
            return Status;
        }
    }

    DEBUG((DEBUG_INFO, "USB stack initialized successfully.\n"));

    // ============= LOAD STORED DEVICE DATA =============
    DEBUG((DEBUG_INFO, "=== TPM STORAGE CHECK ===\n"));
    
    // Initialize the structure
    ZeroMem(&StoredDevice, sizeof(USB_DEVICE));
    UINTN DataSize = sizeof(USB_DEVICE);
    Status = gRT->GetVariable(
                                                        L"DxeHashUsbDevice",
                                                        &gDxeHashNvramGuid,
                                                        NULL,
                                                        &DataSize,
                                                        &SavedDev
                                              );
    // Try to read USB serial from TPM
    Status = ReadUsbSerialFromTpm(StoredDevice.SerialNumber, sizeof(StoredDevice.SerialNumber));
    DEBUG((DEBUG_INFO, "ReadUsbSerialFromTpm Status: %r\n", Status));
    
    if (!EFI_ERROR(Status)) {
        // Try to read combined data (flag + hashes)
        UINT8 RecoveryHash[TPM_HASH_SIZE];
        EFI_STATUS CombinedStatus = ReadCombinedDataFromTpm(&StoredDevice.Flag, StoredDevice.Hash, RecoveryHash);
        DEBUG((DEBUG_INFO, "ReadCombinedDataFromTpm Status: %r\n", CombinedStatus));
        
        if (!EFI_ERROR(CombinedStatus)) {
            DeviceRegistered = TRUE;
            DEBUG((DEBUG_INFO, "STORED DEVICE DATA FROM TPM:\n"));
            DEBUG((DEBUG_INFO, "  Serial: '%s'\n", StoredDevice.SerialNumber));
            DEBUG((DEBUG_INFO, "  Flag: %d\n", SavedDev.Flag));
         /**   
            if (StoredDevice.Flag == 1) {
                Print(L"TPM Check - Serial: %s, Flag: %d (Authentication Mode)\n", 
                      StoredDevice.SerialNumber, StoredDevice.Flag);
            } else {
                Print(L"TPM Check - Serial: %s, Flag: %d (Registration Mode)\n", 
                      StoredDevice.SerialNumber, StoredDevice.Flag);
            }**/
        }
    }
    
    if (!DeviceRegistered) {
        DEBUG((DEBUG_INFO, "No valid device registration found in TPM\n"));
        Print(L"No device found in TPM - Starting initial registration\n");
        StoredDevice.Flag = 0; // Force registration mode
    }
    
    DEBUG((DEBUG_INFO, "=== END TPM CHECK ===\n"));


    
    DEBUG((DEBUG_INFO, "=== DECISION LOGIC ===\n"));
    DEBUG((DEBUG_INFO, "DeviceRegistered: %s\n", DeviceRegistered ? "TRUE" : "FALSE"));
    DEBUG((DEBUG_INFO, "Condition (EFI_ERROR(Status) || StoredDevice.Flag != 1): %s\n", 
           (EFI_ERROR(Status) || StoredDevice.Flag != 1) ? "TRUE (REGISTRATION)" : "FALSE (AUTHENTICATION)"));
    if (EFI_ERROR(Status) || SavedDev.Flag != 1)
    {
        // REGISTRATION MODE
        DEBUG((DEBUG_INFO, "***** ENTERING REGISTRATION MODE (FLAG = 0) *****\n"));
        Print(L"***** REGISTRATION MODE *****\n");
        
        if (DeviceRegistered) {
           // Print(L"Re-registration mode - Existing device will be replaced\n");
            DEBUG((DEBUG_INFO, "Re-registration mode - Existing device will be replaced\n"));
        } else {
            Print(L"Initial registration - No device found in TPM storage\n");
            DEBUG((DEBUG_INFO, "Initial registration - No device found in TPM storage\n"));
        }

        // Initialize TPM storage
        DEBUG((DEBUG_INFO, "Initializing TPM storage...\n"));
        Status = InitializeUsbTpmStorage();
        if (EFI_ERROR(Status)) {
            DEBUG((DEBUG_ERROR, "Failed to initialize TPM storage: %r\n", Status));
            Print(L"Failed to initialize TPM storage: %r\n", Status);
            return Status;
        }

        // Registration 
        while (TRUE)
        {
            Status = gBS->LocateHandleBuffer(ByProtocol, &gEfiUsbIoProtocolGuid, NULL,
                                             &HandleCount, &HandleBuffer);
            if (EFI_ERROR(Status))
            {
                DEBUG((DEBUG_ERROR, "No USB devices found.\n"));
                Print(L"No USB devices found. Waiting...\n");
                gBS->Stall(2000000);
                continue;
            }

            DEBUG((DEBUG_INFO, "Found %d USB devices for registration\n", HandleCount));
            Print(L"Found %d USB devices\n", HandleCount);

            INTN SelectedIndex = SelectUsbDevice(HandleBuffer, HandleCount);
            if (SelectedIndex >= 0)
            {
                Status = gBS->HandleProtocol(
                                                          HandleBuffer[SelectedIndex],
                                                          &gEfiUsbIoProtocolGuid, 
                                                          (VOID **)&UsbIo
                                                    );
                if (!EFI_ERROR(Status))
                {
                    USB_DEVICE NewDevice = {0};
                    CHAR8 UsbInfo[512];
                    
                    Status = GetUsbDeviceDetails(
                        HandleBuffer[SelectedIndex],
                        UsbIo,
                        UsbInfo,
                        sizeof(UsbInfo),
                        &NewDevice.Vid,
                        &NewDevice.Pid,
                        NewDevice.SerialNumber,
                        sizeof(NewDevice.SerialNumber));
                        
                    if (!EFI_ERROR(Status))
                    {
                        // Set the flag for the new device
                        NewDevice.Flag = 1; // Will be set to 1 after successful registration
                        
                        Status = gRT->SetVariable(
                                                              L"DxeHashUsbDevice", 
                                                              &gDxeHashNvramGuid,
                                                              NVRAM_VARIABLE_ATTRIBUTES,
                                                              sizeof(USB_DEVICE),  
                                                              &NewDevice
                                                  );
                        DEBUG((DEBUG_INFO, "SetVariable Status: %r\n", Status));
                        
                        DEBUG((DEBUG_INFO, "=== REGISTERING NEW DEVICE ===\n"));
                        DEBUG((DEBUG_INFO, "VID: 0x%04X\n", NewDevice.Vid));
                        DEBUG((DEBUG_INFO, "PID: 0x%04X\n", NewDevice.Pid));
                        DEBUG((DEBUG_INFO, "Serial: '%s'\n", NewDevice.SerialNumber));
                        DEBUG((DEBUG_INFO, "Flag: %d\n", NewDevice.Flag));
                        
                        Print(L"\nRegistering - \nVID: %04X, \nPID: %04X, \nSerial: %s\n", 
                              NewDevice.Vid, NewDevice.Pid, NewDevice.SerialNumber);

                        // Generate hash for the USB device
                        Status = Tpm2HashUsbDeviceInfo(
                            NewDevice.Vid,
                            NewDevice.Pid,
                            NewDevice.SerialNumber,
                            NewDevice.Hash,
                            sizeof(NewDevice.Hash));
                        
                        if (EFI_ERROR(Status)) {
                            DEBUG((DEBUG_ERROR, "Failed to generate USB device hash: %r\n", Status));
                            Print(L"FAILED to generate device hash: %r\n", Status);
                            continue;
                        }

                        DEBUG((DEBUG_INFO, "Hash generation status: %r\n", Status));
                        DEBUG((DEBUG_INFO, "Hash of USB Device: "));
                        for (UINTN i = 0; i < TPM_HASH_SIZE; i++) {
                            DEBUG((DEBUG_INFO, "%02x", NewDevice.Hash[i]));
                        }  
                        DEBUG((DEBUG_INFO, "\n"));

                        // Store USB serial number to TPM
                        Status = StoreUsbSerialInTpm(NewDevice.SerialNumber);
                        if (EFI_ERROR(Status)) {
                            DEBUG((DEBUG_ERROR, "FAILED to store USB serial in TPM: %r\n", Status));
                            Print(L"FAILED to store device serial: %r\n", Status);
                            continue;
                        }

                        // Generate recovery code and hash
                        CHAR16 RandomN[25] = {0};
                        UINT8 InputD[32] = {0};
                       // UINT8 RecoveryHash[TPM_HASH_SIZE];

                        Status = RngTestEntryPoint(RandomN, sizeof(RandomN));
                        if (!EFI_ERROR(Status))
                        {
                            Print(L"\n\nPlease save this key for Recovery Purpose -> %s\n", RandomN);
                            DEBUG((DEBUG_INFO, "Recovery key generated: %s\n", RandomN));

                            // Generate recovery hash
                             Status = Tpm2HashBuffer(
                                                            (UINT8 *)RandomN,
                                                            StrLen(RandomN) * sizeof(CHAR16),
                                                            InputD, 
                                                            32);
                            if (!EFI_ERROR(Status))
                            {
                             //Print(L"Generated Rnd Num Hash : ");
                             DEBUG((DEBUG_INFO,"Generated Rnd Num Hash : "));
                                for(UINTN i = 0; i < 32; i++) {
                                   //Print(L"%02x", InputD[i]);
                                   DEBUG((DEBUG_INFO,"%02x", InputD[i]));
                                }
                                //Print(L"\n");
                                // Store combined data with flag=1 after successful registration
                                Status = StoreCombinedDataInTpm(NewDevice.Flag, NewDevice.Hash, InputD);
                                DEBUG((DEBUG_INFO, "Combined data storage status (flag=%d): %r\n", NewDevice.Flag, Status));
                                
                                if (EFI_ERROR(Status)) {
                                    DEBUG((DEBUG_ERROR, "FAILED to store combined data in TPM: %r\n", Status));
                                    Print(L"FAILED to store device data: %r\n", Status);
                                    continue;
                                }

                                // Verify the storage immediately
                                USB_DEVICE VerifyDevice = {0};
                                //UINT8 VerifyRecoveryHash[TPM_HASH_SIZE];
                                
                                EFI_STATUS VerifyStatus1 = ReadUsbSerialFromTpm(VerifyDevice.SerialNumber, sizeof(VerifyDevice.SerialNumber));
                                EFI_STATUS VerifyStatus2 = ReadCombinedDataFromTpm(&VerifyDevice.Flag, VerifyDevice.Hash, VerifyDevice.RecoveryHash);
                                

                                if (!EFI_ERROR(VerifyStatus1) && !EFI_ERROR(VerifyStatus2)) {
                                    DEBUG((DEBUG_INFO, "=== VERIFICATION SUCCESSFUL ===\n"));
                                    DEBUG((DEBUG_INFO, "Stored Serial: '%s'\n", VerifyDevice.SerialNumber));
                                    DEBUG((DEBUG_INFO, "Stored Flag: %d (Should be 1)\n", VerifyDevice.Flag));
                                   // Print(L"Status: Device stored successfully in TPM with flag=%d!\n", VerifyDevice.Flag);
                                  //  Print(L"Next boot will use authentication mode.\n");
                                    
                                    // Copy the registered device data back to StoredDevice
                                    CopyMem(&StoredDevice, &NewDevice, sizeof(USB_DEVICE));
                                } else {
                                    DEBUG((DEBUG_ERROR, "VERIFICATION FAILED: Serial=%r, Combined=%r\n", VerifyStatus1, VerifyStatus2));
                                    Print(L"ERROR: Could not verify stored device!\n");
                                }
                            }

                            Print(L"\nUSB device registered successfully!\n");
                            //Print(L"Flag set to %d - Next boot will require authentication.\n", NewDevice.Flag);
                            Print(L"Press ENTER to reboot.\n");
                            DEBUG((DEBUG_INFO, "Registration complete. Flag=%d set. Waiting for ENTER...\n", NewDevice.Flag));
                            
                            EFI_INPUT_KEY Key;
                            while (TRUE)
                            {
                                gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, NULL);
                                gST->ConIn->ReadKeyStroke(gST->ConIn, &Key);
                                if (Key.UnicodeChar == CHAR_CARRIAGE_RETURN)
                                {
                                    Print(L"Rebooting...\n");
                                    DEBUG((DEBUG_INFO, "Rebooting system with flag=%d...\n", NewDevice.Flag));
                                    gBS->Stall(1000000);
                                    gRT->ResetSystem(EfiResetWarm, EFI_SUCCESS, 0, NULL);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            
            if (HandleBuffer != NULL) {
                FreePool(HandleBuffer);
                HandleBuffer = NULL;
            }
            gBS->Stall(3000000);
        }
    }
    else if (StoredDevice.Flag == 1)
    {
        // AUTHENTICATION MODE
        DEBUG((DEBUG_INFO, "***** ENTERING AUTHENTICATION MODE  *****\n"));
        Print(L"***** AUTHENTICATION MODE *****\n");
        Print(L"Device registered - Authentication required\n");
        //Print(L"Looking for device with Serial: %s\n\n", StoredDevice.SerialNumber);

        EFI_INPUT_KEY Key;
        BOOLEAN EscMsgShown = FALSE;

        while (TRUE)
        {
            Status = gBS->LocateHandleBuffer(ByProtocol, &gEfiUsbIoProtocolGuid, NULL,
                                             &HandleCount, &HandleBuffer);

            if (EFI_ERROR(Status))
            {
                DEBUG((DEBUG_ERROR, "No USB devices found during authentication.\n"));
                Print(L"No USB devices found. Scanning again...\n");

                if (!EscMsgShown) {
                    Print(L"Press 'ESC' to start Recovery Mode.\n");
                    EscMsgShown = TRUE;
                }

                if (gST->ConIn->ReadKeyStroke(gST->ConIn, &Key) == EFI_SUCCESS &&
                    Key.UnicodeChar == 0 && Key.ScanCode == SCAN_ESC) {
                    Print(L"\nESC pressed. Entering Recovery Mode...\n");
                    Status = RecoverySystem();
                    return EFI_SUCCESS;
                }

                gBS->Stall(2000000);
                continue;
            }

            DEBUG((DEBUG_INFO, "Found %d USB devices for authentication\n", HandleCount));
            Print(L"Found %d USB devices\n", HandleCount);

            BOOLEAN DeviceFound = FALSE;
            
            // Check each USB device against the stored device
            for (UINTN i = 0; i < HandleCount && !DeviceFound; i++)
            {
                Status = gBS->HandleProtocol(HandleBuffer[i], &gEfiUsbIoProtocolGuid,
                                             (VOID **)&UsbIo);
                if (EFI_ERROR(Status)) {
                    DEBUG((DEBUG_INFO, "Failed to get USB IO protocol for device %d: %r\n", i, Status));
                    continue;
                }

                USB_DEVICE CurrentDevice = {0};
                CHAR8 UsbInfo[512];
                
                Status = GetUsbDeviceDetails(
                                                            HandleBuffer[i],
                                                            UsbIo,
                                                            UsbInfo,
                                                            sizeof(UsbInfo),
                                                            &CurrentDevice.Vid,
                                                            &CurrentDevice.Pid,
                                                            CurrentDevice.SerialNumber,
                                                            sizeof(CurrentDevice.SerialNumber)
                                            );
                if (EFI_ERROR(Status)) {
                    DEBUG((DEBUG_INFO, "Failed to get device details for device %d: %r\n", i, Status));
                    continue;
                }

                DEBUG((DEBUG_INFO, "Checking device %d: VID=0x%04X, PID=0x%04X, Serial='%s'\n", 
                       i, CurrentDevice.Vid, CurrentDevice.Pid, CurrentDevice.SerialNumber));

                // Device matching check with stored device
                BOOLEAN SerialMatch = (StrCmp(CurrentDevice.SerialNumber, StoredDevice.SerialNumber) == 0);
                
                DEBUG((DEBUG_INFO, "Serial match check: %s\n", SerialMatch ? "MATCH" : "NO MATCH"));

                if (SerialMatch)
                {
                    DeviceFound = TRUE;
                    Print(L"\nMATCH FOUND! Starting authentication...\n");
                    DEBUG((DEBUG_INFO, "Device match found. Starting authentication process.\n"));

                    // Authentication process - generate hash from current device
                    Status = Tpm2HashUsbDeviceInfo(
                                                                CurrentDevice.Vid,
                                                                CurrentDevice.Pid,
                                                                CurrentDevice.SerialNumber,
                                                                CurrentDevice.Hash,
                                                                sizeof(CurrentDevice.Hash)
                                                      );
                    if (EFI_ERROR(Status))
                    {
                        Print(L"Failed to hash current device info: %r\n", Status);
                        DEBUG((DEBUG_INFO, "Failed to hash current device info: %r\n", Status));
                        DeviceFound = FALSE;
                        continue;
                    }

                    DEBUG((DEBUG_INFO, "Current Device Hash: "));
                    for (UINTN j = 0; j < TPM_HASH_SIZE; j++)
                    {
                        DEBUG((DEBUG_INFO, "%02x", CurrentDevice.Hash[j]));
                    }
                    DEBUG((DEBUG_INFO, "\n"));

                    DEBUG((DEBUG_INFO, "Stored Device Hash: "));
                    for (UINTN j = 0; j < TPM_HASH_SIZE; j++)
                    {
                        DEBUG((DEBUG_INFO, "%02x", StoredDevice.Hash[j]));
                    }
                    DEBUG((DEBUG_INFO, "\n"));
                    
                    Print(L"\nAuthentication Process initiated....\n");
                    DEBUG((DEBUG_INFO, "\nAuthentication Process initiated....\n"));
                    gBS->Stall(2000000);

                    // Hash comparison with retry logic
                    UINTN HashMismatchCount = 0;
                    BOOLEAN AuthSuccess = FALSE;
                    
                    while (HashMismatchCount < 3 && !AuthSuccess)
                    {
                        if (CompareMem(CurrentDevice.Hash, StoredDevice.Hash, TPM_HASH_SIZE) == 0)
                        {
                            Print(L"USB Device hash matched successfully!\n");
                            DEBUG((DEBUG_INFO, "USB Device hash matched successfully!\n"));
                            
                            // Keep flag=1 after successful authentication
                            Print(L"Authentication successful\n");
                            DEBUG((DEBUG_INFO, "Authentication successful - Flag remains %d\n", StoredDevice.Flag));
                            
                            Print(L"Proceeding to boot.....\n");
                            gBS->Stall(2000000);
                            DEBUG((DEBUG_INFO, "Proceeding to boot.....\n"));
                            
                            AuthSuccess = TRUE;
                            DEBUG((DEBUG_INFO, "USB Device authentication completed.\n"));
                            gBS->Stall(200000);

                            if (HandleBuffer != NULL)
                                FreePool(HandleBuffer);
                            return EFI_SUCCESS;
                        }
                        else
                        {
                            HashMismatchCount++;
                            Print(L"Hash mismatch attempt %d/3.\n", HashMismatchCount);
                            DEBUG((DEBUG_INFO, "Hash mismatch attempt %d/3.\n", HashMismatchCount));

                            if (HashMismatchCount >= 3)
                            {
                                Print(L"3 consecutive USB device hash mismatches. Entering recovery mode...\n");
                                DEBUG((DEBUG_INFO, "3 consecutive USB device hash mismatches. Entering recovery mode...\n"));
                                gBS->Stall(1000000);
                                
                                Status = RecoverySystem();
                                if(EFI_ERROR(Status)){
                                  Print(L"Failed to initialize Recovery Mode: %r\n", Status);
                                }

                                if (HandleBuffer != NULL)
                                    FreePool(HandleBuffer);
                                return EFI_ACCESS_DENIED;
                            }

                            gBS->Stall(1000000);
                        }
                    }
                    
                    // If we get here, authentication failed for this device
                    if (!AuthSuccess) {
                        DeviceFound = FALSE; // Reset to continue searching
                    }
                }
            }

            // Clean up handle buffer after checking all devices
            if (HandleBuffer != NULL) {
                FreePool(HandleBuffer);
                HandleBuffer = NULL;
            }

            // If no matching device was found in this scan
            if (!DeviceFound)
            {
                Print(L"No matching USB device found. Scanning again...\n");
                DEBUG((DEBUG_INFO, "No matching device found in this scan cycle.\n"));
                
                if (!EscMsgShown)
                {
                    Print(L"\nPress 'ESC' to start Recovery Mode.\n\n");
                    EscMsgShown = TRUE;
                }

                // Check if ESC key was pressed
                if (gST->ConIn->ReadKeyStroke(gST->ConIn, &Key) == EFI_SUCCESS &&
                    Key.UnicodeChar == 0 && Key.ScanCode == SCAN_ESC)
                {
                    Print(L"\nESC key pressed. Entering Recovery Mode...\n");
                    gBS->Stall(1000000);
                    DEBUG((DEBUG_INFO, "ESC key pressed. Entering Recovery Mode...\n"));
                    Status = RecoverySystem();
                    return EFI_SUCCESS;
                }

                gBS->Stall(2000000);
            }
        }
    }
    else
    { 
        if (HandleBuffer != NULL) {
                FreePool(HandleBuffer);
                HandleBuffer = NULL;
            }
    }
    
    return EFI_SUCCESS;
}
