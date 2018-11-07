
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

static fa_task_t MakeTask(uint64_t session_id, uint32_t user_id,
                          uint32_t cmd, uint32_t base)
{
  fa_task_t task;
  memset(&task, base, sizeof(fa_task_t));
  task.version = 1;
  task.session_id = session_id;
  task.user_id = user_id;
  task.cmd = cmd;
  task.face.version = 1;
  task.face.valid = 0;
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
  for (int users = 1; users <= MAX_NUM_USERS; ++users) {
    Run(MakeTask(0x0, users, FACEAUTH_CMD_ERASE, 0x00),
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

TEST_F(FaceAuthTest, FullMatchMismatchTest) {
  uint64_t session_id = 0xFACE000022220000ull;
  for (int i = 0; i < 20; ++i) {
    session_id++;
    Run(MakeTask(session_id, 0x1, FACEAUTH_CMD_ENROLL, (i == 17) ? 0x11 : 0x0),
        MakeResult(session_id, FACEAUTH_SUCCESS, FACEAUTH_NOMATCH));
  }

  for (int i = 0; i < 20; ++i) {
    session_id++;
    Run(MakeTask(session_id, 0x2, FACEAUTH_CMD_ENROLL, (i == 11) ? 0xAA : 0x0),
        MakeResult(session_id, FACEAUTH_SUCCESS, FACEAUTH_NOMATCH));
  }

  session_id++;
  Run(MakeTask(session_id, 0x1, FACEAUTH_CMD_COMP, 0x11),
      MakeResult(session_id, FACEAUTH_SUCCESS, FACEAUTH_MATCH));
  session_id++;
  Run(MakeTask(session_id, 0x1, FACEAUTH_CMD_COMP, 0xAA),
      MakeResult(session_id, FACEAUTH_SUCCESS, FACEAUTH_NOMATCH));
  session_id++;
  Run(MakeTask(session_id, 0x2, FACEAUTH_CMD_COMP, 0x11),
      MakeResult(session_id, FACEAUTH_SUCCESS, FACEAUTH_NOMATCH));
  session_id++;
  Run(MakeTask(session_id, 0x2, FACEAUTH_CMD_COMP, 0xAA),
      MakeResult(session_id, FACEAUTH_SUCCESS, FACEAUTH_MATCH));
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

TEST_F(FaceAuthTest, InvalidUserTest) {
  uint64_t session_id = 0xFACE000055550000ull;
  session_id++;
  Run(MakeTask(session_id, 0x0, FACEAUTH_CMD_ENROLL, 0x0),
      MakeResult(session_id, FACEAUTH_ERR_INVALID_ARGS, FACEAUTH_NOMATCH));
  session_id++;
  Run(MakeTask(session_id, 0x4, FACEAUTH_CMD_ENROLL, 0x0),
      MakeResult(session_id, FACEAUTH_ERR_INVALID_ARGS, FACEAUTH_NOMATCH));
}

TEST_F(FaceAuthTest, InvalidCommandTest) {
  uint64_t session_id = 0xFACE000066660000ull;
  session_id++;
  Run(MakeTask(session_id, 0x1, 0x0, 0x0),
      MakeResult(session_id, FACEAUTH_ERR_INVALID_ARGS, FACEAUTH_NOMATCH));
}

}

