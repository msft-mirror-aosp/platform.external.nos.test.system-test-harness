#include "gtest/gtest.h"
#include "avb_tools.h"
#include "keymaster_tools.h"
#include "nugget_tools.h"
#include "nugget/app/keymaster/keymaster.pb.h"
#include "nugget/app/keymaster/keymaster_defs.pb.h"
#include "nugget/app/keymaster/keymaster_types.pb.h"
#include "Keymaster.client.h"
#include "util.h"

#include "src/blob.h"
#include "src/macros.h"
#include "src/test-data/test-keys/rsa.h"

#include "openssl/bn.h"
#include "openssl/ec_key.h"
#include "openssl/nid.h"
#include "openssl/sha.h"

using std::cout;
using std::string;
using std::unique_ptr;

using namespace nugget::app::keymaster;

using namespace test_data;

namespace {

class ImportWrappedKeyTest: public testing::Test {
 protected:
  static unique_ptr<nos::NuggetClientInterface> client;
  static unique_ptr<Keymaster> service;
  static unique_ptr<test_harness::TestHarness> uart_printer;

  static void SetUpTestCase();
  static void TearDownTestCase();
};

unique_ptr<nos::NuggetClientInterface> ImportWrappedKeyTest::client;
unique_ptr<Keymaster> ImportWrappedKeyTest::service;
unique_ptr<test_harness::TestHarness> ImportWrappedKeyTest::uart_printer;

void ImportWrappedKeyTest::SetUpTestCase() {
  uart_printer = test_harness::TestHarness::MakeUnique();

  client = nugget_tools::MakeNuggetClient();
  client->Open();
  EXPECT_TRUE(client->IsOpen()) << "Unable to connect";

  service.reset(new Keymaster(*client));

  // Do setup that is normally done by the bootloader.
  keymaster_tools::SetRootOfTrust(client.get());
  keymaster_tools::SetBootState(client.get());
}

void ImportWrappedKeyTest::TearDownTestCase() {
  client->Close();
  client = unique_ptr<nos::NuggetClientInterface>();

  uart_printer = nullptr;
}

/* Wrapped key DER just for reference; fields below have been pulled
 * out from here. */
/*const static uint8_t WRAPPED_KEY_DER[] = {
  0x30, 0x82, 0x01, 0x5f, 0x02, 0x01, 0x00, 0x04, 0x82, 0x01, 0x00, 0x5e,
  0x46, 0xac, 0x96, 0x21, 0x12, 0x0e, 0x1f, 0x4c, 0x45, 0x92, 0x5f, 0xe2,
  0x43, 0x5c, 0xac, 0x77, 0xc7, 0x71, 0x62, 0xdb, 0x0c, 0xda, 0xc4, 0x89,
  0xac, 0x2c, 0xfd, 0x7a, 0x88, 0xb7, 0x04, 0x46, 0x74, 0x4b, 0x76, 0x68,
  0x65, 0xf9, 0x32, 0xd5, 0xa5, 0xaf, 0xe5, 0x7f, 0xaf, 0x94, 0x89, 0x73,
  0x7a, 0x51, 0xca, 0x9c, 0x42, 0xd5, 0x5d, 0x0a, 0xe9, 0x94, 0x8f, 0x01,
  0x54, 0xd7, 0x4a, 0x78, 0x72, 0x05, 0xea, 0x67, 0x70, 0xf7, 0xc8, 0x61,
  0x9f, 0xa2, 0xdf, 0x16, 0xbe, 0x4b, 0x42, 0xd5, 0xe1, 0xf4, 0x18, 0x93,
  0x41, 0xd8, 0x2e, 0x53, 0x0c, 0xfd, 0x6c, 0x3d, 0x5a, 0x3b, 0x4a, 0x01,
  0xa9, 0x8c, 0x6c, 0x58, 0x55, 0x95, 0xc5, 0x19, 0xa8, 0x72, 0x4d, 0xc7,
  0x87, 0x90, 0xe6, 0x2b, 0x8f, 0x8d, 0xc3, 0x91, 0x1d, 0xc7, 0x56, 0xd7,
  0xb9, 0x3a, 0xea, 0x46, 0x43, 0xdf, 0x26, 0x50, 0x83, 0xf1, 0x13, 0xf7,
  0xd5, 0x2c, 0xb1, 0x20, 0xf5, 0xee, 0xb2, 0xdc, 0xc1, 0x0d, 0xfe, 0x4e,
  0x08, 0x5a, 0x66, 0x89, 0xfa, 0x67, 0x00, 0x94, 0xc5, 0xe3, 0x54, 0xb7,
  0x0b, 0x69, 0x84, 0x1a, 0x55, 0xf8, 0x2a, 0xaf, 0x13, 0x0b, 0x4b, 0x67,
  0x2a, 0xd4, 0xb1, 0x59, 0x9c, 0x74, 0x49, 0x93, 0x5b, 0x25, 0x0b, 0x0d,
  0xf7, 0x71, 0x2e, 0x60, 0x0e, 0x5d, 0x52, 0x76, 0x2b, 0xc2, 0xb9, 0x42,
  0x74, 0x7c, 0xa2, 0x83, 0xde, 0xe3, 0x30, 0xcb, 0xab, 0xf4, 0x27, 0xea,
  0xe0, 0xdd, 0x33, 0x07, 0x06, 0x7e, 0x11, 0xa4, 0xfd, 0xe4, 0x7e, 0xd5,
  0xea, 0xb0, 0x2c, 0x83, 0xd2, 0xad, 0x33, 0x91, 0x6d, 0xe6, 0xe9, 0x09,
  0x9f, 0x24, 0x33, 0xbf, 0x74, 0xf0, 0xfd, 0xcf, 0x1e, 0x34, 0x65, 0x4d,
  0x73, 0x72, 0x0a, 0xfa, 0x8d, 0x69, 0xe1, 0x68, 0xc6, 0xb8, 0x05, 0x0b,
  0x37, 0x2e, 0x86, 0x04, 0x0c, 0xd7, 0x96, 0xb0, 0x2c, 0x37, 0x0f, 0x1f,
  0xa4, 0xcc, 0x01, 0x24, 0xf1, 0x30, 0x14, 0x02, 0x01, 0x03, 0x30, 0x0f,
  0xa1, 0x02, 0x31, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x20, 0xa3, 0x04, 0x02,
  0x02, 0x01, 0x00, 0x04, 0x20, 0xcc, 0xd5, 0x40, 0x85, 0x5f, 0x83, 0x3a,
  0x5e, 0x14, 0x80, 0xbf, 0xd2, 0xd3, 0x6f, 0xaf, 0x3a, 0xee, 0xe1, 0x5d,
  0xf5, 0xbe, 0xab, 0xe2, 0x69, 0x1b, 0xc8, 0x2d, 0xde, 0x2a, 0x7a, 0xa9,
  0x10, 0x04, 0x10, 0x0a, 0xa4, 0x6a, 0x14, 0xa0, 0x24, 0x90, 0xea, 0xf5,
  0xef, 0x32, 0x86, 0x2e, 0x4c, 0x03, 0x4e
};*/

static const uint8_t RSA_ENVELOPE[] = {
  0x99, 0xb0, 0xad, 0xd4, 0xe4, 0x0c, 0x82, 0x37, 0x33, 0x0c, 0x12, 0xe1,
  0x2a, 0x5c, 0x22, 0x5b, 0xdc, 0xb4, 0x36, 0xae, 0xb5, 0xb1, 0x90, 0xbb,
  0xc7, 0x09, 0x13, 0xe4, 0x12, 0xf2, 0x5b, 0x20, 0x3e, 0xe5, 0xd2, 0x6d,
  0x69, 0x25, 0xa8, 0x3e, 0x59, 0x43, 0x31, 0x3a, 0x29, 0x06, 0x97, 0xae,
  0x0f, 0x30, 0x38, 0x18, 0x6e, 0x3a, 0xac, 0x6a, 0xb7, 0xa4, 0x36, 0x87,
  0xc4, 0xde, 0xdb, 0xa3, 0x46, 0x78, 0x64, 0xd7, 0x2b, 0x51, 0x51, 0x34,
  0x36, 0x98, 0x66, 0x72, 0xd2, 0x48, 0x98, 0x61, 0x67, 0x87, 0xcf, 0x29,
  0xba, 0x9b, 0xf7, 0xcd, 0x14, 0x33, 0xd2, 0x67, 0x9b, 0x9c, 0x55, 0x3b,
  0xf0, 0x72, 0x13, 0x75, 0xbc, 0x55, 0x95, 0xd9, 0x0d, 0xb3, 0xe5, 0x6b,
  0x88, 0x4a, 0xae, 0xe5, 0xc0, 0xf2, 0x17, 0x01, 0x92, 0xfb, 0x68, 0x08,
  0x8e, 0x91, 0x96, 0x5f, 0x2f, 0x19, 0x63, 0xeb, 0x95, 0xb2, 0xd2, 0x89,
  0x5b, 0xb5, 0x96, 0xa6, 0x6f, 0x50, 0x63, 0x6d, 0x05, 0x9f, 0x06, 0x29,
  0x81, 0xc2, 0x85, 0x3a, 0xd0, 0x63, 0x78, 0xc8, 0x78, 0x95, 0xde, 0x49,
  0xa1, 0xb7, 0xdd, 0xde, 0xaf, 0x6a, 0xa2, 0xf6, 0xb5, 0xe2, 0x51, 0x21,
  0xad, 0x5e, 0x81, 0xa3, 0x2c, 0xf4, 0xb5, 0x5d, 0x1f, 0x7e, 0x45, 0xe8,
  0xdc, 0x7c, 0xab, 0x3b, 0xaa, 0x49, 0xee, 0xa9, 0xd5, 0x9d, 0xe1, 0x78,
  0x39, 0xe9, 0xb4, 0x91, 0xf7, 0x2e, 0xbf, 0xc5, 0xbc, 0xb5, 0x26, 0x48,
  0x05, 0x9f, 0x49, 0x31, 0xa7, 0xa2, 0x56, 0xea, 0x79, 0x61, 0x28, 0x23,
  0x67, 0x8e, 0x12, 0xbd, 0x4b, 0xe7, 0xbd, 0x8f, 0x10, 0x45, 0xbc, 0x3c,
  0xd0, 0x4b, 0xa9, 0x28, 0xd2, 0xf3, 0x59, 0xfb, 0x10, 0x08, 0xd0, 0x91,
  0x74, 0xd8, 0xd1, 0x89, 0x6c, 0xda, 0xc7, 0x6e, 0x4f, 0x44, 0x09, 0x89,
  0x4f, 0x2d, 0x7c, 0xa7
};

static const uint8_t INITIALIZATION_VECTOR[] = {
  0xd7, 0x96, 0xb0, 0x2c, 0x37, 0x0f, 0x1f, 0xa4, 0xcc, 0x01, 0x24, 0xf1
};

static const uint8_t ENCRYPTED_IMPORT_KEY[] = {
  0xcc, 0xd5, 0x40, 0x85, 0x5f, 0x83, 0x3a, 0x5e, 0x14, 0x80, 0xbf, 0xd2,
  0xd3, 0x6f, 0xaf, 0x3a, 0xee, 0xe1, 0x5d, 0xf5, 0xbe, 0xab, 0xe2, 0x69,
  0x1b, 0xc8, 0x2d, 0xde, 0x2a, 0x7a, 0xa9, 0x10
};

static const uint8_t AAD[] = {
  0x30, 0x14, 0x02, 0x01, 0x03, 0x30, 0x0f, 0xa1, 0x02, 0x31, 0x00, 0xa2,
  0x03, 0x02, 0x01, 0x20, 0xa3, 0x04, 0x02, 0x02, 0x01, 0x00
};

static const uint8_t GCM_TAG[] = {
    0x0a, 0xa4, 0x6a, 0x14, 0xa0, 0x24, 0x90, 0xea, 0xf5, 0xef, 0x32, 0x86,
    0x2e, 0x4c, 0x03, 0x4e
};

/* g3/experimental/users/franksalim/keyimport/keys/private.pem */
static uint8_t wrapping_key_N[] = {
  0x55, 0xdd, 0x21, 0x28, 0xa6, 0x8f, 0xbd, 0xa2, 0xcc, 0x33, 0x48, 0x3f,
  0xed, 0x2a, 0x1d, 0x72, 0xc6, 0x8f, 0x0f, 0xf1, 0x82, 0xd2, 0x01, 0x0e,
  0xb0, 0x4c, 0x23, 0x85, 0xf1, 0x58, 0x74, 0x8d, 0x2a, 0x1c, 0xe7, 0xdf,
  0x1d, 0xc6, 0x24, 0x20, 0xc4, 0x14, 0xcf, 0xf5, 0x6a, 0x28, 0x0b, 0x60,
  0x09, 0xec, 0x5c, 0x2f, 0x5b, 0x7e, 0xc2, 0xb5, 0x7d, 0x72, 0x2b, 0xb9,
  0xcc, 0xec, 0x3c, 0xa1, 0x2b, 0xf0, 0x36, 0x95, 0x5f, 0xa9, 0x72, 0x01,
  0x8b, 0xd4, 0xd0, 0x91, 0x49, 0xee, 0xa7, 0xc3, 0x0a, 0xe6, 0xc3, 0xdf,
  0xe0, 0x42, 0xa6, 0x85, 0xe3, 0x4d, 0x50, 0x4b, 0x45, 0x7c, 0x6d, 0xa9,
  0x95, 0x2a, 0xe0, 0x53, 0x67, 0xc3, 0x23, 0x21, 0x8a, 0x85, 0xec, 0x5d,
  0xf7, 0xbe, 0xe0, 0x92, 0x67, 0x79, 0x49, 0xc4, 0x11, 0x74, 0x42, 0x86,
  0x38, 0x4c, 0x37, 0xc1, 0xf5, 0x11, 0x5c, 0x64, 0xf4, 0x0b, 0xac, 0xf7,
  0x0c, 0x1c, 0xd6, 0x03, 0x67, 0x3c, 0xd3, 0xe5, 0xe4, 0x43, 0x26, 0x68,
  0x8f, 0x71, 0xef, 0x6f, 0x40, 0x57, 0xc1, 0x47, 0x13, 0xea, 0xfa, 0x1f,
  0x92, 0xd5, 0x7b, 0x2d, 0x31, 0xbe, 0x23, 0x0d, 0x7c, 0xfe, 0xba, 0x0e,
  0xff, 0x21, 0xc4, 0x88, 0xda, 0x7c, 0x0b, 0x1f, 0x91, 0x02, 0x5b, 0x24,
  0xdf, 0x5a, 0xd5, 0xc1, 0xb5, 0x1c, 0x0a, 0xc9, 0x2b, 0xd8, 0x18, 0x5c,
  0xfb, 0x1e, 0x84, 0x35, 0x2d, 0xe3, 0xea, 0x54, 0x28, 0x9c, 0x75, 0xbb,
  0x41, 0xdc, 0xbd, 0xac, 0x86, 0xef, 0x3f, 0x0a, 0x15, 0x25, 0xc7, 0xb1,
  0x56, 0x3d, 0x31, 0x37, 0xa8, 0x73, 0xe6, 0x06, 0x7b, 0x93, 0xdb, 0x43,
  0xfb, 0x18, 0x00, 0xd5, 0xfe, 0xc1, 0x94, 0xd1, 0x34, 0x3f, 0x3f, 0x65,
  0xfc, 0xe1, 0x70, 0x7d, 0x7f, 0x06, 0xb0, 0x56, 0xce, 0x00, 0x89, 0x1d,
  0x93, 0x67, 0xc3, 0xae
};

/* g3/experimental/users/franksalim/keyimport/keys/private.pem */
static uint8_t wrapping_key_D[] = {
  0x81, 0x61, 0xf8, 0xb4, 0xd8, 0xf8, 0x34, 0x1a, 0xb5, 0xe3, 0x01, 0xf1,
  0xe5, 0x28, 0xb1, 0x98, 0x66, 0xd0, 0xa2, 0x34, 0xe0, 0x52, 0xaf, 0xb0,
  0x0f, 0x54, 0x3d, 0x4c, 0xcb, 0xd2, 0xb2, 0x03, 0xdc, 0x24, 0xbf, 0xdb,
  0x0d, 0xbe, 0x8c, 0x6e, 0xc5, 0xe6, 0x51, 0xf8, 0xd7, 0xbd, 0x0f, 0xa2,
  0x5b, 0x86, 0x81, 0x62, 0x69, 0xa8, 0x37, 0x37, 0x66, 0x5b, 0xa0, 0x5b,
  0x5a, 0x9d, 0x65, 0x52, 0xc6, 0x41, 0xbb, 0x45, 0x6b, 0x0d, 0x4a, 0x8f,
  0xe0, 0xf7, 0xca, 0xa5, 0x98, 0x8d, 0x2d, 0x31, 0xcc, 0x07, 0x74, 0xad,
  0xd5, 0xdd, 0xbb, 0x57, 0xa9, 0xc4, 0x18, 0xd6, 0xfc, 0xb8, 0x55, 0x4c,
  0x47, 0xd7, 0xc4, 0xb1, 0x28, 0xf2, 0x91, 0x7e, 0xdd, 0xcd, 0x88, 0x28,
  0x27, 0x97, 0x50, 0x5a, 0xdc, 0xe4, 0x36, 0xc5, 0x20, 0x0e, 0x8d, 0xee,
  0xd7, 0x2c, 0x3d, 0x0e, 0x49, 0xbf, 0x3e, 0x0c, 0x90, 0x00, 0x0a, 0xae,
  0x2a, 0xa0, 0x9b, 0x57, 0xd2, 0xe6, 0x95, 0x1c, 0x4d, 0x48, 0xb4, 0x9f,
  0xb2, 0xfe, 0x70, 0xf6, 0x45, 0x8a, 0xba, 0x40, 0xc9, 0x63, 0x7d, 0x08,
  0xff, 0xcc, 0x2b, 0x82, 0x1c, 0x18, 0x0d, 0x07, 0x72, 0x10, 0xea, 0x5f,
  0x7a, 0x29, 0xde, 0xb6, 0xae, 0x9e, 0x1e, 0xe7, 0xbe, 0x52, 0x0e, 0x08,
  0x43, 0x2c, 0x5d, 0x3b, 0x68, 0xdc, 0x3a, 0xa0, 0x30, 0xb6, 0x10, 0xe7,
  0xf9, 0x6d, 0x76, 0x27, 0xdb, 0x9b, 0x95, 0x88, 0x7a, 0xc6, 0x14, 0x4f,
  0xe2, 0x7f, 0x1f, 0x64, 0x40, 0xda, 0x2c, 0x4e, 0x41, 0x74, 0x0f, 0x4f,
  0xaf, 0xee, 0xae, 0x5c, 0x78, 0x4d, 0x1e, 0xb9, 0xb8, 0xf8, 0x33, 0xd8,
  0x88, 0xe1, 0x0d, 0xe7, 0x2d, 0x6c, 0x04, 0x60, 0x09, 0x63, 0xb6, 0x52,
  0x1a, 0x71, 0xf3, 0x99, 0x6f, 0xe7, 0x1e, 0x2b, 0x11, 0x08, 0x19, 0x25,
  0xb6, 0x47, 0x14, 0x43
};

const uint8_t IMPORTED_KEY[32] = {
  0x8a, 0x28, 0xf1, 0xa8, 0xb8, 0x93, 0x8a, 0x2c, 0x1f, 0x35, 0x72, 0xb0,
  0x4c, 0x48, 0xd5, 0xdf, 0x52, 0x28, 0x1e, 0xe2, 0x11, 0xad, 0x73, 0xf7,
  0x7f, 0x97, 0x04, 0xe6, 0x79, 0x29, 0xff, 0xcf
};

TEST_F(ImportWrappedKeyTest, ImportSuccess) {
  ImportWrappedKeyRequest request;
  ImportKeyResponse response;
  const uint8_t masking_key[32] = {};
  struct km_blob blob;

  /* TODO: do key generation via rpc. */
  memset(&blob, 0, sizeof(blob));
  blob.b.algorithm = BLOB_RSA;
  blob.b.key.rsa.rsa.e = 65537;
  blob.b.key.rsa.rsa.N.dmax = sizeof(wrapping_key_N) / sizeof(uint32_t);
  blob.b.key.rsa.rsa.d.dmax = sizeof(wrapping_key_D) / sizeof(uint32_t);

  memcpy(&blob.b.key.rsa.N_bytes, wrapping_key_N, sizeof(wrapping_key_N));
  memcpy(&blob.b.key.rsa.d_bytes, wrapping_key_D, sizeof(wrapping_key_D));

  blob.b.tee_enforced.params[0].tag = Tag::PADDING;
  blob.b.tee_enforced.params[0].integer = PaddingMode::PADDING_RSA_OAEP;
  blob.b.tee_enforced.params_count++;
  blob.b.tee_enforced.params[1].tag = Tag::PURPOSE;
  blob.b.tee_enforced.params[1].integer = KeyPurpose::WRAP_KEY;
  blob.b.tee_enforced.params_count++;
  SHA256(reinterpret_cast<const uint8_t *>(&blob),
         sizeof(struct km_blob) - SHA256_DIGEST_LENGTH,
         reinterpret_cast<uint8_t *>(&blob.hmac));

  request.set_key_format(KeyFormat::RAW);
  KeyParameters *params = request.mutable_params();
  KeyParameter *param = params->add_params();
  param->set_tag(Tag::ALGORITHM);
  param->set_integer((uint32_t)Algorithm::AES);

  request.set_rsa_envelope(RSA_ENVELOPE, sizeof(RSA_ENVELOPE));
  request.set_initialization_vector(INITIALIZATION_VECTOR,
                                     sizeof(INITIALIZATION_VECTOR));
  request.set_encrypted_import_key(ENCRYPTED_IMPORT_KEY,
                                    sizeof(ENCRYPTED_IMPORT_KEY));
  request.set_aad(AAD, sizeof(AAD));
  request.set_gcm_tag(GCM_TAG, sizeof(GCM_TAG));
  request.mutable_wrapping_key_blob()->set_blob(&blob, sizeof(blob));
  request.set_masking_key(masking_key, sizeof(masking_key));

  ASSERT_NO_ERROR(service->ImportWrappedKey(request, &response), "");
  EXPECT_EQ((ErrorCode)response.error_code(), ErrorCode::OK);

  EXPECT_EQ(sizeof(struct km_blob), response.blob().blob().size());
  const struct km_blob *response_blob =
      (const struct km_blob *)response.blob().blob().data();
  EXPECT_EQ(response_blob->b.key.sym.key_bits >> 3, sizeof(IMPORTED_KEY));
  EXPECT_EQ(memcmp(response_blob->b.key.sym.bytes, IMPORTED_KEY,
                   sizeof(IMPORTED_KEY)), 0);
}

} // namespace
