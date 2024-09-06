#include <std/mem.pat>

struct UTF16CStr {
    char16 data[while(std::mem::read_unsigned($, 2) != 0x0)];
    char16 terminator[[hidden]];
};

enum LicenseType : u16 {
    Unknown = 0,
    App = 1,
    Lease = 2,
    Device = 3,
    Dev = 4,
    Lob = 5,
    Upgrade = 6,
};

bitfield BasicPolicies {
    lease_required : 1;
    is_primary : 1;
    expired : 1;
    is_device_locked : 1;
    padding : 12;
};

struct LicenseInformation {
    u16 version;
    LicenseType type;
    s32 issued;
    BasicPolicies policies;
};

// SHA256 of PFN (lowercase)
struct LicenseEntryId {
    u8 data[32];
};

enum PolicyType : u8 {
    NONE = 0x01,
    STRING = 0x11,
    BINARY = 0x31,
    DWORD = 0x41,
    MULTI_SZ = 0x71
};

struct Policy {
    u16 something1[[hidden]];
    u16 something2[[hidden]];
    u8 pad0[[hidden]];
    PolicyType type;
    u16 pad1[[hidden]];
    u16 priority;
    u16 name_sz;
    u16 data_sz;
    char16 name[name_sz / 2];
    
    u32 end = $ + data_sz;
    match (type) {
        (PolicyType::STRING): {
            UTF16CStr data;
        }
        (PolicyType::DWORD): {
            u32 data;
        }
        (PolicyType::MULTI_SZ): {
            UTF16CStr data[];
        }
        (_): {
            u8 data[while($ < end)];
        }
    }
    u16 terminator[[hidden]];
};

enum BlockType : u32 {
    SignedBlock = 0x14,
    DeviceLicenseExpirationTime = 0x1f,
    PollingTime = 0xd3,
    LicenseExpirationTime = 0x20,
    ClepSignState = 0x12d,
    LicenseDeviceId = 0xd2,
    UnkBlock1 = 0xd1,
    LicenseId = 0xcb,
    HardwareId = 0xd0,
    UnkBlock2 = 0xcf,
    UplinkKeyId = 0x18,
    UnkBlock3 = 0x0,
    UnkBlock4 = 0x12e,
    UnkBlock5 = 0xd5,
    PackageFullName = 0xce,
    LicenseInformation = 0xc9,
    PackedContentKeys = 0xca,
    EncryptedDeviceKey = 0x1,
    DeviceLicenseDeviceId = 0x2,
    LicenseEntryIds = 0xcd,
    LicensePolicies = 0xd4,
    KeyholderPublicSigningKey = 0xdc,
    KeyholderPolicies = 0xdd,
    KeyholderKeyLicenseId = 0xde,
    SignatureBlock = 0xcc,
};




struct TLVBlock {
    BlockType type;
    u32 size;
    
    u32 end = $ + size;
    match (type) {
        (BlockType::SignedBlock): {
            TLVBlock block[while($ < end)];
        }
        (BlockType::DeviceLicenseExpirationTime | BlockType::PollingTime | BlockType::LicenseExpirationTime): {
            s32 time;
        }
        (BlockType::PackageFullName): {
            UTF16CStr name;
        }
        (BlockType::LicenseInformation): {
            LicenseInformation information;
        }
        (BlockType::LicenseEntryIds): {
            u16 count[[hidden]];
            LicenseEntryId ids[count];
        }
        (BlockType::LicensePolicies): {
            Policy policies[while($ < end)];
        }
        (BlockType::SignatureBlock): {
            u16 something0[[hidden]];
            u16 origin;
            u8 data[while($ < end)];
        }
        (_): { u8 data[size]; }
    }
};



TLVBlock blocks[while($ < std::mem::size())] @ 0;