
#include <app_nugget.h>
#include <nos/NuggetClientInterface.h>
#include <gtest/gtest.h>

#include <memory>

#include "user/faceauth/include/fa_common.h"

#include "nugget_tools.h"
#include "util.h"

using std::string;
using std::vector;
using std::unique_ptr;

namespace {

class FaceAuthTest: public testing::Test {
 protected:
  void SetUp() override;

  static void SetUpTestCase();
  static void TearDownTestCase();

  static unique_ptr<nos::NuggetClientInterface> client;
  static unique_ptr<test_harness::TestHarness> uart_printer;

  static void Run(const fa_task_t task, const fa_result_t expected);

  static void FullMatchMismatchTest(uint32_t profile1, uint32_t profile2,
                                    uint32_t slot1, uint32_t slot2);
};

unique_ptr<nos::NuggetClientInterface> FaceAuthTest::client;
unique_ptr<test_harness::TestHarness> FaceAuthTest::uart_printer;

void FaceAuthTest::SetUpTestCase() {
  uart_printer = test_harness::TestHarness::MakeUnique();

  client = nugget_tools::MakeNuggetClient();
  client->Open();
  EXPECT_TRUE(client->IsOpen()) << "Unable to connect";
}

void FaceAuthTest::TearDownTestCase() {
  client->Close();
  client = unique_ptr<nos::NuggetClientInterface>();

  uart_printer = nullptr;
}

uint8_t CalcCrc8(const uint8_t *data, int len)
{
  unsigned crc = 0;
  int i, j;

  for (j = len; j; j--, data++) {
    crc ^= (*data << 8);
    for (i = 8; i; i--) {
      if (crc & 0x8000) {
        crc ^= (0x1070 << 3);
      }
      crc <<= 1;
    }
  }

  return (uint8_t)(crc >> 8);
}

static fa_task_t MakeTask(uint64_t session_id, uint32_t profile_id,
                          uint32_t cmd, uint32_t base)
{
  fa_task_t task;
  memset(&task, base, sizeof(fa_task_t));
  task.header.version = 1;
  task.header.session_id = session_id;
  task.header.profile_id = profile_id;
  task.header.cmd = cmd;
  task.header.crc = CalcCrc8(reinterpret_cast<const uint8_t*>(&task.header),
                             offsetof(struct fa_task_header_t, crc));
  task.face.version = 1;
  task.face.valid = 0;
  task.face.crc = CalcCrc8(reinterpret_cast<const uint8_t*>(&task.face),
                           offsetof(struct fa_embedding_t, crc));

  return task;
}

static fa_result_t MakeResult(uint64_t session_id, int32_t error,
                              int32_t match)
{
  fa_result_t result;
  result.version = 1;
  result.session_id = session_id;
  result.error = error;
  result.match = match;
  result.complete = 1;
  result.crc = CalcCrc8(reinterpret_cast<const uint8_t*>(&result),
                        offsetof(struct fa_result_t, crc));
  return result;
}

static vector<uint8_t> Task2Buffer(const fa_task_t* task)
{
  vector<uint8_t> buffer;
  for (size_t i = 0; i < sizeof(fa_task_t); ++i) {
    buffer.push_back(*(reinterpret_cast<const uint8_t*>(task) + i));
  }
  return buffer;
}

static const fa_result_t Buffer2Result(const vector<uint8_t>& buffer)
{
  const fa_result_t result = *(reinterpret_cast<const fa_result_t*>(
                               buffer.data()));
  return result;
}

static void EXPECT_RESULT_EQ(const fa_result_t& r1, const fa_result_t& r2)
{
  EXPECT_EQ(r1.version, r2.version);
  EXPECT_EQ(r1.session_id, r2.session_id);
  EXPECT_EQ(r1.error, r2.error);
  EXPECT_EQ(r1.match, r2.match);
  EXPECT_EQ(r1.complete, r2.complete);
}

void FaceAuthTest::Run(const fa_task_t task, const fa_result_t expected)
{
  vector<uint8_t> buffer;
  buffer.resize(1024);
  ASSERT_NO_ERROR(FaceAuthTest::client->CallApp(
         APP_ID_FACEAUTH_TEST, 1, Task2Buffer(&task), &buffer), "");
  const fa_result_t observed = Buffer2Result(buffer);
  EXPECT_RESULT_EQ(expected, observed);
}

void FaceAuthTest::SetUp() {
  for (int profiles = 1; profiles <= MAX_NUM_PROFILES; ++profiles) {
    Run(MakeTask(0x0, profiles, FACEAUTH_CMD_ERASE, 0x00),
        MakeResult(0x0, FACEAUTH_SUCCESS, FACEAUTH_NOMATCH));
  }
}

TEST_F(FaceAuthTest, SimpleMatchMismatchTest) {
  uint64_t session_id = 0xFACE000011110000ull;
  session_id++;
  Run(MakeTask(session_id, 0x1, FACEAUTH_CMD_COMP, 0x11),
      MakeResult(session_id, FACEAUTH_SUCCESS, FACEAUTH_NOMATCH));
  session_id++;
  Run(MakeTask(session_id, 0x1, FACEAUTH_CMD_ENROLL, 0x11),
      MakeResult(session_id, FACEAUTH_SUCCESS, FACEAUTH_NOMATCH));
  session_id++;
  Run(MakeTask(session_id, 0x1, FACEAUTH_CMD_COMP, 0x11),
      MakeResult(session_id, FACEAUTH_SUCCESS, FACEAUTH_MATCH));
  session_id++;
  Run(MakeTask(session_id, 0x1, FACEAUTH_CMD_ERASE, 0x00),
      MakeResult(session_id, FACEAUTH_SUCCESS, FACEAUTH_NOMATCH));
  session_id++;
  Run(MakeTask(session_id, 0x1, FACEAUTH_CMD_COMP, 0x11),
      MakeResult(session_id, FACEAUTH_SUCCESS, FACEAUTH_NOMATCH));
}

void FaceAuthTest::FullMatchMismatchTest(uint32_t profile1, uint32_t profile2,
                                         uint32_t slot1, uint32_t slot2) {
  uint64_t session_id = 0xFACE000022220000ull;
  for (uint32_t i = 0; i < 20; ++i) {
    session_id++;
    Run(MakeTask(session_id, profile1, FACEAUTH_CMD_ENROLL,
                (i == slot1) ? 0x11 : 0x0),
        MakeResult(session_id, FACEAUTH_SUCCESS, FACEAUTH_NOMATCH));
    session_id++;
    Run(MakeTask(session_id, profile2, FACEAUTH_CMD_ENROLL,
                (i == slot2) ? 0xAA : 0x0),
        MakeResult(session_id, FACEAUTH_SUCCESS, FACEAUTH_NOMATCH));
  }

  session_id++;
  Run(MakeTask(session_id, profile1, FACEAUTH_CMD_COMP, 0x11),
      MakeResult(session_id, FACEAUTH_SUCCESS, FACEAUTH_MATCH));
  session_id++;
  Run(MakeTask(session_id, profile1, FACEAUTH_CMD_COMP, 0xAA),
      MakeResult(session_id, FACEAUTH_SUCCESS, FACEAUTH_NOMATCH));
  session_id++;
  Run(MakeTask(session_id, profile2, FACEAUTH_CMD_COMP, 0x11),
      MakeResult(session_id, FACEAUTH_SUCCESS, FACEAUTH_NOMATCH));
  session_id++;
  Run(MakeTask(session_id, profile2, FACEAUTH_CMD_COMP, 0xAA),
      MakeResult(session_id, FACEAUTH_SUCCESS, FACEAUTH_MATCH));
}

TEST_F(FaceAuthTest, ExhaustiveMatchMismatchTest) {
  FullMatchMismatchTest(1, 6,  0, 19);
  FullMatchMismatchTest(2, 5,  1, 18);
  FullMatchMismatchTest(3, 4,  2, 17);
  SetUp();
  FullMatchMismatchTest(2, 4,  3, 16);
  FullMatchMismatchTest(1, 5,  4, 15);
  FullMatchMismatchTest(3, 6,  5, 14);
  SetUp();
  FullMatchMismatchTest(3, 5,  6, 13);
  FullMatchMismatchTest(1, 4,  7, 12);
  FullMatchMismatchTest(2, 6,  8, 11);
  SetUp();
  FullMatchMismatchTest(3, 6,  9, 10);
}

TEST_F(FaceAuthTest, SFSFullTest) {
  uint64_t session_id = 0xFACE000033330000ull;
  for (int i = 0; i < 20; ++i) {
    session_id++;
    Run(MakeTask(session_id, 0x1, FACEAUTH_CMD_ENROLL, 0x0),
        MakeResult(session_id, FACEAUTH_SUCCESS, FACEAUTH_NOMATCH));
  }

  session_id++;
  Run(MakeTask(session_id, 0x1, FACEAUTH_CMD_ENROLL, 0x0),
      MakeResult(session_id, FACEAUTH_ERR_SFS_FULL, FACEAUTH_NOMATCH));
}

TEST_F(FaceAuthTest, LockoutTest) {
  uint64_t session_id = 0xFACE000044440000ull;
  for (int i = 0; i < 5; ++i) {
    session_id++;
    Run(MakeTask(session_id, 0x1, FACEAUTH_CMD_COMP, 0x0),
        MakeResult(session_id, FACEAUTH_SUCCESS, FACEAUTH_NOMATCH));
  }

  session_id++;
  Run(MakeTask(session_id, 0x1, FACEAUTH_CMD_COMP, 0x0),
      MakeResult(session_id, FACEAUTH_ERR_THROTTLE, FACEAUTH_NOMATCH));
}

TEST_F(FaceAuthTest, ValidProfileIDTest) {
  uint64_t session_id = 0xFACE000055550000ull;
  session_id++;
  Run(MakeTask(session_id, 0x0, FACEAUTH_CMD_ENROLL, 0x0),
      MakeResult(session_id, FACEAUTH_ERR_INVALID_ARGS, FACEAUTH_NOMATCH));

  for (int i = 1; i <= MAX_NUM_PROFILES; ++i) {
    session_id++;
    Run(MakeTask(session_id, i, FACEAUTH_CMD_ENROLL, 0x0),
        MakeResult(session_id, FACEAUTH_SUCCESS, FACEAUTH_NOMATCH));
  }

  session_id++;
  Run(MakeTask(session_id, MAX_NUM_PROFILES + 1, FACEAUTH_CMD_ENROLL, 0x0),
      MakeResult(session_id, FACEAUTH_ERR_INVALID_ARGS, FACEAUTH_NOMATCH));
}

TEST_F(FaceAuthTest, InvalidCommandTest) {
  uint64_t session_id = 0xFACE000066660000ull;
  session_id++;
  Run(MakeTask(session_id, 0x1, 0x0, 0x0),
      MakeResult(session_id, FACEAUTH_ERR_INVALID_ARGS, FACEAUTH_NOMATCH));
}

}

