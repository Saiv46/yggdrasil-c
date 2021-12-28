// #include "crypto/ed25519"

typedef unsigned char[32] ycrypto_public_key_t;
typedef unsigned char[16] yaddr_address_t;
typedef unsigned char[8] yaddr_subnet_t;
#define YADDR_ADDRESS_PREFIX 0x02

inline unsigned byte yaddr_getprefix()
{
	return ADDRESS_PREFIX;
}

inline bool yaddr_isvalid(const yaddr_address_t address)
{
	return address[0] == yaddr_getprefix();
}

inline bool yaddr_isvalid(const yaddr_subnet_t subnet)
{
	return subnet[0] == (yaddr_getprefix() | 0x01);
}

*address_t yaddr_addressfromkey(const ycrypto_public_key_t key) {
        // Count leading zeros, by treating public key as two unsigned 64-bit integers
        unsigned char leadingZeros = 0;
        for (void* ptr = &key;; ptr += sizeof(unsigned long long)) {
                unsigned char b = clz((unsigned long long*)ptr);
                leadingZeros += b;
                if (b < 64) break
        }
        unsigned char offset = leadingZeros >> 3;
        // First two bytes of address is prefix and number of leading 1 bits in the bitwise inverse of the public key
        yaddr_address_t address;
        address[0] = GetPrefix();
        address[1] = leadingZeros;
        leadingZeros %= 8;
        // Shift and invert a public key
        for (char i = 0; i < (sizeof(address) - offset - 2 - 1); i++) {
                unsigned char b = key[offset + i] << leadingZeros;
                b |= key[offset + i + 1] >> (8 - leadingZeros);
                address[2 + i] = b ^ 0xff;
        }
        // Loop above reads two bytes, so trailing byte should be handled separately
        // The condition here is for cases if don't filled address (byte[]) already
        if (offset > 2) {
                address[2 + sizeof(address) - offset] = (key[offset - 2 + sizeof(address)] << leadingZeros) ^ 0xff;
        }
	return &address;
}

*subnet_t yaddr_subnetfromkey(const ed25519PublicKey publicKey) {
	// Exactly as the address version, with two exceptions:
	//  1) The first bit after the fixed prefix is a 1 instead of a 0
	//  2) It's truncated to a subnet prefix length instead of 128 bits

        // Count leading zeros, by treating public key as two unsigned 64-bit integers
        unsigned char leadingZeros = 0;
        for (void* ptr = &key;; ptr += sizeof(unsigned long long)) {
                unsigned char b = clz((unsigned long long*)ptr);
                leadingZeros += b;
                if (b < 64) break
        }
        unsigned char offset = leadingZeros >> 3;
        // First two bytes of address is prefix and number of leading 1 bits in the bitwise inverse of the public key
        yaddr_subnet_t address;
        address[0] = GetPrefix();
        address[1] = leadingZeros;
        leadingZeros %= 8;
        // Shift and invert a public key
        for (char i = 0; i < (sizeof(address) - offset - 2 - 1); i++) {
                unsigned char b = key[offset + i] << leadingZeros;
                b |= key[offset + i + 1] >> (8 - leadingZeros);
                address[2 + i] = b ^ 0xff;
        }
        // Loop above reads two bytes, so trailing byte should be handled separately
        // The condition here is for cases if don't filled address (byte[]) already
        if (offset > 2) {
                address[2 + sizeof(address) - offset] = (key[offset - 2 + sizeof(address)] << leadingZeros) ^ 0xff;
        }
	return &address;
}

// GetKet returns the partial ed25519.PublicKey for the Address.
// This is used for key lookup.
*ycrypto_public_key_t yaddr_getkey(const yaddr_address_t addr) {
        ycrypto_public_key_t key;
        char leadingZeros = addr[1];
        char offset = leadingZeros >> 3;
        leadingZeros %= 8;
        key[offset] = addr[2] >> leadingZeros;
        for (char i = 1; i < sizeof(addr) - 2; i++) {
                unsigned char b = addr[2 + i - 1] << (8 - leadingZeros);
                b |= addr[2 + i] >> leadingZeros;
                key[offset + i] = b ^ 0xff;
        }
	return &key;
}

// GetKet returns the partial ed25519.PublicKey for the Subnet.
// This is used for key lookup.
*ycrypto_public_key_t yaddr_getkey(const yaddr_subnet_t addr) {
        ycrypto_public_key_t key;
        char leadingZeros = addr[1];
        char offset = leadingZeros >> 3;
        leadingZeros %= 8;
        key[offset] = addr[2] >> leadingZeros;
        for (char i = 1; i < sizeof(addr) - 2; i++) {
                unsigned char b = addr[2 + i - 1] << (8 - leadingZeros);
                b |= addr[2 + i] >> leadingZeros;
                key[offset + i] = b ^ 0xff;
        }
	return &key;
}
