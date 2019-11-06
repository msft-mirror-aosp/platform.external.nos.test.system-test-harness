
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

vector<uint8_t> EMBEDDING_VECTOR_NULL(128, 0);
const vector<uint8_t> EMBEDDING_VECTOR_1(64, 16);
const vector<uint8_t> EMBEDDING_VECTOR_2(64, (uint8_t)-16);

const uint32_t PROFILE_1 = 1;
const uint32_t PROFILE_2 = 2;
const uint32_t PROFILE_3 = 3;
const uint32_t PROFILE_4 = 4;
const uint32_t PROFILE_5 = 5;
const uint32_t PROFILE_6 = 6;

class FaceAuthTest: public testing::Test {
 public:
  static unique_ptr<nos::NuggetClientInterface> client;
  static unique_ptr<test_harness::TestHarness> uart_printer;

 protected:
  void SetUp() override;

  static void SetUpTestCase();
  static void TearDownTestCase();
  static void DisengageGlobalLockout();
};

unique_ptr<nos::NuggetClientInterface> FaceAuthTest::client;
unique_ptr<test_harness::TestHarness> FaceAuthTest::uart_printer;

void FaceAuthTest::SetUpTestCase() {
  srand(time(NULL));
  uart_printer = test_harness::TestHarness::MakeUnique();

  client = nugget_tools::MakeNuggetClient();
  client->Open();
  EXPECT_TRUE(client->IsOpen()) << "Unable to connect";

  /* We need any embedding vector to have magnitude of 128 */
  EMBEDDING_VECTOR_NULL[127] = 128;
  DisengageGlobalLockout();
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

class Task {
 public:
  Task(uint32_t profile_id, uint32_t cmd,
       uint32_t version = FACEAUTH_MIN_ABH_VERSION) {
    memset(&task, 0, sizeof(task));
    task.version = version;
    task.session_id = 0xFACEBEEFBEEFFACEull;
    task.profile_id = profile_id;
    task.cmd = cmd;
  }

  Task& SetFirst(uint64_t first) {
    task.input.data.first = first;
    return *this;
  }

  Task& SetChallenge(uint64_t challenge) {
    memcpy(task.input.challenge, &challenge, sizeof(challenge));
    return *this;
  }

  Task& Finalize() {
    task.crc = CalcCrc8(reinterpret_cast<const uint8_t*>(&task),
                        offsetof(struct fa_task_t, crc));
    return *this;
  }

  vector<uint8_t> ToBuffer() {
    vector<uint8_t> buffer;
    for (size_t i = 0; i < sizeof(fa_task_t); ++i) {
      buffer.push_back(*(reinterpret_cast<const uint8_t*>(&task) + i));
    }
    return buffer;
  }

 private:
  fa_task_t task;
};

class Embedding {
 public:
  Embedding() { memset(&embed, 0, sizeof(embed)); }
  Embedding(vector<uint8_t> base, uint32_t version = 1) {
    memset(&embed, 0, sizeof(embed));
    embed.version = version;
    embed.valid = 0;
    std::copy(base.begin(), base.end(), &embed.face_id[0]);
    std::copy(base.begin(), base.end(), &embed.depth_id[0]);
  }

  void Finalize() {
    embed.crc = CalcCrc8(reinterpret_cast<const uint8_t*>(&embed),
                         offsetof(struct fa_embedding_t, crc));
  }

  vector<uint8_t> ToBuffer() {
    vector<uint8_t> buffer;
    for (size_t i = 0; i < sizeof(fa_embedding_t); ++i) {
      buffer.push_back(*(reinterpret_cast<const uint8_t*>(&embed) + i));
    }
    return buffer;
  }

 private:
  fa_embedding_t embed;
};

class Token {
 public:
  Token() { memset(&token, 0, sizeof(token)); }

  Token(fa_token_t token) : token(token) {}

  Token(uint64_t challenge, uint64_t user_id, uint64_t auth_id) {
    memset(&token, 0, sizeof(token));
    token.challenge = challenge;
    token.user_id = user_id;
    token.authenticator_id = auth_id;
  }

  vector<uint8_t> ToBuffer() {
    vector<uint8_t> buffer;
    for (size_t i = 0; i < sizeof(fa_token_t); ++i) {
      buffer.push_back(*(reinterpret_cast<const uint8_t*>(&token) + i));
    }
    return buffer;
  }

  fa_token_t GetRaw() { return token; }

 private:
  fa_token_t token;
};

class Result {
 public:
  Result() { memset(&result, 0, sizeof(result)); }

  Result(fa_result_t result) : result(result) {}

  Result(int32_t error) {
    memset(&result, 0, sizeof(result));
    SetError(error);
  }

  fa_result_t GetRaw() {
    Finalize();
    return result;
  }

  Result& SetError(int32_t error) {
    result.error = error;
    return *this;
  }

  Result& SetChallenge(uint64_t challenge) {
    memcpy(result.output.challenge, &challenge, sizeof(challenge));
    return *this;
  }

  Result& SetSecond(uint32_t second) {
    result.output.data.second = second;
    return *this;
  }

  Result& SetThird(uint32_t third) {
    result.output.data.third = third;
    return *this;
  }

  uint64_t GetChallenge() {
    uint64_t challenge;
    memcpy(&challenge, result.output.challenge, sizeof(challenge));
    return challenge;
  }

  uint32_t GetFirst() { return result.output.data.first; }
  uint32_t GetSecond() { return result.output.data.second; }

  Result& Finalize() {
    result.version = 1;
    result.session_id = 0xFACEBEEFBEEFFACEull;
    result.complete = 1;
    result.crc = CalcCrc8(reinterpret_cast<const uint8_t*>(&result),
                          offsetof(struct fa_result_t, crc));
    return *this;
  }

 protected:
  fa_result_t result;
};

static void EXPECT_REQ(Result r1, Result r2) {
  fa_result_t observed = r1.GetRaw();
  fa_result_t expected = r2.GetRaw();

  EXPECT_EQ(observed.version, expected.version);
  EXPECT_EQ(observed.session_id, expected.session_id);
  EXPECT_EQ(observed.error, expected.error);
  EXPECT_EQ(observed.output.data.first, expected.output.data.first);
  EXPECT_EQ(observed.output.data.second, expected.output.data.second);
  EXPECT_EQ(observed.output.data.third, expected.output.data.third);
  EXPECT_EQ(observed.complete, expected.complete);
  EXPECT_EQ(observed.crc, expected.crc);
}

class ResetLockoutResult : public Result {
 public:
  ResetLockoutResult(Result result) : Result(result) {}

  ResetLockoutResult(int32_t error) : Result(error) {}

  ResetLockoutResult& SetLockoutEvent(uint32_t lockout_event) {
    result.output.data.third = lockout_event;
    return *this;
  }
};

class MigrateResult : public Result {
 public:
  MigrateResult(Result result) : Result(result) {}

  MigrateResult(int32_t error) : Result(error) {}

  MigrateResult& SetEmbeddingNum(uint32_t num) {
    result.output.data.second = num;
    return *this;
  }

  MigrateResult& SetMatch(bool m) {
    result.output.data.third = m;
    return *this;
  }
};

class AuthenticateResult : public Result {
 public:
  AuthenticateResult(Result result, Token token)
      : Result(result), token(token) {}

  AuthenticateResult(int32_t error) : Result(error) {}

  AuthenticateResult& SetMatch(bool m) {
    result.output.data.first = m;
    return *this;
  }

  AuthenticateResult& SetLockoutEvent(uint32_t lockout_event) {
    result.output.data.third = lockout_event;
    return *this;
  }

  Token GetToken() { return token; }

 protected:
  Token token;
};

static void EXPECT_AEQ(AuthenticateResult r1, AuthenticateResult r2) {
  EXPECT_REQ(r1, r2);

  fa_token_t observed = r1.GetToken().GetRaw();
  fa_token_t expected = r2.GetToken().GetRaw();

  EXPECT_EQ(observed.challenge, expected.challenge);
  EXPECT_EQ(observed.user_id, expected.user_id);
  EXPECT_EQ(observed.authenticator_id, expected.authenticator_id);
}

class Transaction {
 public:
  Transaction(Task task, Embedding embed, Token token)
      : input_task(task), input_embed(embed), input_token(token) {}

  Transaction& Finalize() {
    input_task.Finalize();
    input_embed.Finalize();
    return *this;
  }

  Transaction& Run() {
    vector<uint8_t> task = input_task.ToBuffer();
    vector<uint8_t> embed = input_embed.ToBuffer();
    vector<uint8_t> token = input_token.ToBuffer();

    vector<uint8_t> buffer_rx;
    buffer_rx.resize(512);

    vector<uint8_t> buffer_tx;
    buffer_tx.insert(buffer_tx.end(), task.begin(), task.end());
    buffer_tx.insert(buffer_tx.end(), embed.begin(), embed.end());
    buffer_tx.insert(buffer_tx.end(), token.begin(), token.end());

    FaceAuthTest::client->CallApp(APP_ID_FACEAUTH_TEST, 1, buffer_tx,
                                  &buffer_rx);

    struct fa_output_t {
      fa_result_t result;
      fa_token_t token;
    } __attribute__((packed));

    fa_output_t output =
        *(reinterpret_cast<struct fa_output_t*>(buffer_rx.data()));

    output_result = output.result;
    output_token = output.token;

    return *this;
  }

  Result GetResult() { return Result(output_result); }
  Token GetToken() { return Token(output_token); }

 private:
  Task input_task;
  Embedding input_embed;
  Token input_token;
  fa_result_t output_result;
  fa_token_t output_token;
};

class Device {
 public:
  static Result Erase(uint32_t profile_id) {
    return Transaction(Task(profile_id, FACEAUTH_CMD_ERASE), Embedding(),
                       Token())
        .Finalize()
        .Run()
        .GetResult();
  }

  static Result GenerateChallenge() {
    Result ret =
        Transaction(Task(0, FACEAUTH_CMD_GET_CHALLENGE), Embedding(), Token())
            .Finalize()
            .Run()
            .GetResult();
    memcpy(&challenge, ret.GetRaw().output.challenge, sizeof(challenge));
    return ret;
  }

  static Result RevokeChallenge() {
    return Transaction(Task(0, FACEAUTH_CMD_REVOKE_CHALLENGE), Embedding(),
                       Token())
        .Finalize()
        .Run()
        .GetResult();
  }

  static uint64_t GetChallenge() { return challenge; }

 private:
  static uint64_t challenge;
};

uint64_t Device::challenge;

void FaceAuthTest::SetUp() {
  for (int i = 0; i < MAX_NUM_PROFILES; ++i)
    EXPECT_REQ(Device::Erase(i + 1), Result(FACEAUTH_SUCCESS));
}

void FaceAuthTest::DisengageGlobalLockout() {
  /* Send Auth Token */
  Result generate_result = Device::GenerateChallenge();
  EXPECT_REQ(generate_result,
             Result(FACEAUTH_SUCCESS).SetChallenge(Device::GetChallenge()));
  EXPECT_REQ(Transaction(Task(PROFILE_1, FACEAUTH_CMD_ENROLL).Finalize(),
                         Embedding(EMBEDDING_VECTOR_1, 1),
                         Token(Device::GetChallenge(), 0, 0))
                 .Run()
                 .GetResult(),
             Result(FACEAUTH_ERR_CRC));
}

TEST_F(FaceAuthTest, OldFirmwareVersionShouldError) {
  EXPECT_REQ(Transaction(Task(PROFILE_1, FACEAUTH_CMD_ERASE,
                              FACEAUTH_MIN_ABH_VERSION - 0x100),
                         Embedding(), Token())
                 .Finalize()
                 .Run()
                 .GetResult(),
             Result(FACEAUTH_ERR_VERSION));
}

TEST_F(FaceAuthTest, NewFirmwareVersionShouldNotError) {
  EXPECT_REQ(Transaction(Task(PROFILE_1, FACEAUTH_CMD_ERASE,
                              FACEAUTH_MIN_ABH_VERSION + 0x100),
                         Embedding(), Token())
                 .Finalize()
                 .Run()
                 .GetResult(),
             Result(FACEAUTH_SUCCESS));
}

TEST_F(FaceAuthTest, TaskCRCErrorShouldBeDetected) {
  EXPECT_REQ(
      Transaction(Task(PROFILE_1, FACEAUTH_CMD_ERASE), Embedding(), Token())
          .Run()
          .GetResult(),
      Result(FACEAUTH_ERR_CRC));
}

TEST_F(FaceAuthTest, ZeroChallengeShouldError) {
  EXPECT_REQ(Transaction(Task(PROFILE_1, FACEAUTH_CMD_ENROLL),
                         Embedding(EMBEDDING_VECTOR_1, 1), Token())
                 .Finalize()
                 .Run()
                 .GetResult(),
             Result(FACEAUTH_ERR_INVALID_CHALLENGE));
  EXPECT_REQ(Transaction(Task(PROFILE_1, FACEAUTH_CMD_SET_FEATURE),
                         Embedding(EMBEDDING_VECTOR_1, 1), Token())
                 .Finalize()
                 .Run()
                 .GetResult(),
             Result(FACEAUTH_ERR_INVALID_CHALLENGE));
  EXPECT_REQ(Transaction(Task(PROFILE_1, FACEAUTH_CMD_CLR_FEATURE),
                         Embedding(EMBEDDING_VECTOR_1, 1), Token())
                 .Finalize()
                 .Run()
                 .GetResult(),
             Result(FACEAUTH_ERR_INVALID_CHALLENGE));
}

TEST_F(FaceAuthTest, InvalidChallengeShouldError) {
  Result generate_result = Device::GenerateChallenge();
  EXPECT_REQ(generate_result,
             Result(FACEAUTH_SUCCESS).SetChallenge(Device::GetChallenge()));

  EXPECT_REQ(Transaction(Task(PROFILE_1, FACEAUTH_CMD_ENROLL),
                         Embedding(EMBEDDING_VECTOR_1, 1), Token(rand(), 0, 0))
                 .Finalize()
                 .Run()
                 .GetResult(),
             Result(FACEAUTH_ERR_INVALID_CHALLENGE));
  EXPECT_REQ(Transaction(Task(PROFILE_1, FACEAUTH_CMD_SET_FEATURE),
                         Embedding(EMBEDDING_VECTOR_1, 1), Token(rand(), 0, 0))
                 .Finalize()
                 .Run()
                 .GetResult(),
             Result(FACEAUTH_ERR_INVALID_CHALLENGE));
  EXPECT_REQ(Transaction(Task(PROFILE_1, FACEAUTH_CMD_CLR_FEATURE),
                         Embedding(EMBEDDING_VECTOR_1, 1), Token(rand(), 0, 0))
                 .Finalize()
                 .Run()
                 .GetResult(),
             Result(FACEAUTH_ERR_INVALID_CHALLENGE));
}

TEST_F(FaceAuthTest, EmbeddingCRCErrorShouldBeDetected) {
  EXPECT_REQ(Transaction(Task(PROFILE_1, FACEAUTH_CMD_COMP).Finalize(),
                         Embedding(EMBEDDING_VECTOR_1, 1), Token())
                 .Run()
                 .GetResult(),
             Result(FACEAUTH_ERR_CRC));
  EXPECT_REQ(Transaction(Task(PROFILE_1, FACEAUTH_CMD_MIGRATE).Finalize(),
                         Embedding(EMBEDDING_VECTOR_1, 1), Token())
                 .Run()
                 .GetResult(),
             Result(FACEAUTH_ERR_CRC));

  Result generate_result = Device::GenerateChallenge();
  EXPECT_REQ(generate_result,
             Result(FACEAUTH_SUCCESS).SetChallenge(Device::GetChallenge()));
  EXPECT_REQ(Transaction(Task(PROFILE_1, FACEAUTH_CMD_ENROLL).Finalize(),
                         Embedding(EMBEDDING_VECTOR_1, 1),
                         Token(Device::GetChallenge(), 0, 0))
                 .Run()
                 .GetResult(),
             Result(FACEAUTH_ERR_CRC));
}

TEST_F(FaceAuthTest, InvalidCommandShouldError) {
  Task task(PROFILE_1, 0);
  Embedding embed;
  Token token;

  EXPECT_REQ(Transaction(task, embed, token).Finalize().Run().GetResult(),
             Result(FACEAUTH_ERR_INVALID_ARGS));
}

TEST_F(FaceAuthTest, ValidProfileIDTest) {
  Embedding embed;
  Token token;

  EXPECT_REQ(Transaction(Task(0, FACEAUTH_CMD_GET_USER_INFO), embed, token)
                 .Finalize()
                 .Run()
                 .GetResult(),
             Result(FACEAUTH_ERR_INVALID_ARGS));

  for (int i = 1; i <= MAX_NUM_PROFILES; ++i) {
    EXPECT_REQ(Transaction(Task(i, FACEAUTH_CMD_GET_USER_INFO), embed, token)
                   .Finalize()
                   .Run()
                   .GetResult(),
               Result(FACEAUTH_SUCCESS));
  }

  EXPECT_REQ(Transaction(Task(MAX_NUM_PROFILES + 1, FACEAUTH_CMD_GET_USER_INFO),
                         embed, token)
                 .Finalize()
                 .Run()
                 .GetResult(),
             Result(FACEAUTH_ERR_INVALID_ARGS));
}

class User {
 public:
  User(vector<uint8_t> embed_base) : embed_base(embed_base) {
    user_id = rand();
    user_id <<= 32;
    user_id += rand();
  }

  User& SetEmbeddingVersion(uint8_t version) {
    embed_version = version;
    return *this;
  }

  User& SetEmbeddingBase(vector<uint8_t> base) {
    embed_base = base;
    return *this;
  }

  User& SetUserID(uint64_t sid) {
    user_id = sid;
    return *this;
  }

  Result GetProfileInfo() {
    return Transaction(Task(0, FACEAUTH_CMD_GET_PROFILE_INFO), Embedding(),
                       Token(0, user_id, 0))
        .Finalize()
        .Run()
        .GetResult();
  }

  Result GetUserInfo(uint32_t profile_id) {
    return Transaction(Task(profile_id, FACEAUTH_CMD_GET_USER_INFO),
                       Embedding(), Token())
        .Finalize()
        .Run()
        .GetResult();
  }

  Result Enroll(uint32_t profile_id) {
    Result generate_result = Device::GenerateChallenge();
    EXPECT_REQ(generate_result,
               Result(FACEAUTH_SUCCESS).SetChallenge(Device::GetChallenge()));

    Result ret = Transaction(Task(profile_id, FACEAUTH_CMD_ENROLL),
                             Embedding(embed_base, embed_version),
                             Token(Device::GetChallenge(), user_id, 0))
                     .Finalize()
                     .Run()
                     .GetResult();

    uint64_t auth_id_temp = ret.GetChallenge();
    memcpy(&auth_id, &auth_id_temp, sizeof(auth_id));
    EXPECT_REQ(Device::RevokeChallenge(), Result(FACEAUTH_SUCCESS));

    return ret;
  }

  MigrateResult Migrate(uint32_t profile_id, bool should_migrate) {
    return Transaction(
               Task(profile_id, FACEAUTH_CMD_MIGRATE).SetFirst(should_migrate),
               Embedding(embed_base, embed_version), Token(0, user_id, 0))
        .Finalize()
        .Run()
        .GetResult();
  }

  AuthenticateResult Authenticate(uint32_t profile_id) {
    operation_id = rand();
    operation_id <<= 32;
    operation_id += rand();

    Transaction t =
        Transaction(
            Task(profile_id, FACEAUTH_CMD_COMP).SetChallenge(operation_id),
            Embedding(embed_base, embed_version), Token())
            .Finalize()
            .Run();

    return AuthenticateResult(t.GetResult(), t.GetToken());
  }

  ResetLockoutResult ResetLockout(uint32_t profile_id) {
    Result generate_result = Device::GenerateChallenge();
    EXPECT_REQ(generate_result,
               Result(FACEAUTH_SUCCESS).SetChallenge(Device::GetChallenge()));

    Result ret =
        Transaction(Task(profile_id, FACEAUTH_CMD_RESET_LOCKOUT), Embedding(),
                    Token(Device::GetChallenge(), user_id, 0))
            .Finalize()
            .Run()
            .GetResult();

    EXPECT_REQ(Device::RevokeChallenge(), Result(FACEAUTH_SUCCESS));

    return ret;
  }

  bool IsProfileLocked(uint32_t profile_id) {
    return (GetUserInfo(profile_id).GetSecond() > 0);
  }

  void LockProfile(uint32_t profile_id) {
    vector<uint8_t> original_embed_base = embed_base;
    embed_base = EMBEDDING_VECTOR_NULL;
    /* Fail Authentication 4 times */
    for (int i = 0; i < 4; ++i) {
      EXPECT_REQ(Authenticate(profile_id),
                 AuthenticateResult(FACEAUTH_SUCCESS).SetMatch(false));
    }

    /* Fifth Authentication failure should trigger lockout event */
    EXPECT_REQ(Authenticate(profile_id),
               AuthenticateResult(FACEAUTH_SUCCESS)
                   .SetMatch(false)
                   .SetLockoutEvent(FACEAUTH_LOCKOUT_ENFORCED));

    embed_base = original_embed_base;
  }

  uint32_t GetFeature(uint32_t profile_id) {
    return GetUserInfo(profile_id).GetFirst();
  }

  Result SetFeature(uint32_t profile_id, uint32_t feature) {
    Result generate_result = Device::GenerateChallenge();
    EXPECT_REQ(generate_result,
               Result(FACEAUTH_SUCCESS).SetChallenge(Device::GetChallenge()));

    Result ret =
        Transaction(
            Task(profile_id, FACEAUTH_CMD_SET_FEATURE).SetFirst(feature),
            Embedding(), Token(Device::GetChallenge(), user_id, 0))
            .Finalize()
            .Run()
            .GetResult();

    EXPECT_REQ(Device::RevokeChallenge(), Result(FACEAUTH_SUCCESS));

    return ret;
  }

  Result ClrFeature(uint32_t profile_id, uint32_t feature) {
    Result generate_result = Device::GenerateChallenge();
    EXPECT_REQ(generate_result,
               Result(FACEAUTH_SUCCESS).SetChallenge(Device::GetChallenge()));

    Result ret =
        Transaction(
            Task(profile_id, FACEAUTH_CMD_CLR_FEATURE).SetFirst(feature),
            Embedding(), Token(Device::GetChallenge(), user_id, 0))
            .Finalize()
            .Run()
            .GetResult();

    EXPECT_REQ(Device::RevokeChallenge(), Result(FACEAUTH_SUCCESS));

    return ret;
  }

  uint64_t GetOperationID() { return operation_id; }
  uint64_t GetAuthID() { return auth_id; }
  uint64_t GetUserID() { return user_id; }

 private:
  uint64_t operation_id;
  uint64_t auth_id = 0;
  uint64_t user_id;
  vector<uint8_t> embed_base;
  uint8_t embed_version;
};

class SuccessfulAuthenticateResult : public AuthenticateResult {
 public:
  SuccessfulAuthenticateResult(User u) : AuthenticateResult(FACEAUTH_SUCCESS) {
    token = Token(u.GetOperationID(), u.GetUserID(), u.GetAuthID());
    SetMatch(true);
  }
};

TEST_F(FaceAuthTest, GetProfileInfoTest) {
  vector<User> users;
  for (int i = 0; i < MAX_NUM_PROFILES; ++i) {
    users.push_back(User(EMBEDDING_VECTOR_1));
    users[i].SetEmbeddingVersion(1);
  }

  users[0].SetUserID(0x1122334455667788);
  users[1].SetUserID(0x1122334455667788);
  users[3].SetUserID(0x1122334455667788);

  for (int i = 0; i < MAX_NUM_PROFILES; ++i) users[i].Enroll(i + 1);

  union {
    uint8_t map[8] = {0};
    uint64_t info;
  };

  for (int i = 0; i < MAX_NUM_PROFILES; ++i) {
    for (int j = 0; j < MAX_NUM_PROFILES; ++j) {
      map[i] |= ((users[i].GetUserID() == users[j].GetUserID()) << j);
    }
  }

  for (int i = 0; i < MAX_NUM_PROFILES; ++i) {
    map[MAX_NUM_PROFILES] = map[i];
    EXPECT_REQ(users[i].GetProfileInfo(),
               Result(FACEAUTH_SUCCESS).SetChallenge(info));
    EXPECT_REQ(users[i].GetUserInfo(i + 1),
               Result(FACEAUTH_SUCCESS).SetThird(map[i]));
  }
}

TEST_F(FaceAuthTest, EnrollShouldOnlyAcceptSameUser) {
  User user1(EMBEDDING_VECTOR_1);
  user1.SetEmbeddingVersion(1);

  User user2(EMBEDDING_VECTOR_NULL);
  user2.SetEmbeddingVersion(1);

  /* User 1 Enroll to Profile 1 */
  Result enroll_result = user1.Enroll(PROFILE_1);
  EXPECT_REQ(enroll_result,
             Result(FACEAUTH_SUCCESS).SetChallenge(user1.GetAuthID()));

  /* User 2 Enroll to Profile 1 should fail */
  enroll_result = user2.Enroll(PROFILE_1);
  EXPECT_REQ(enroll_result, Result(FACEAUTH_ERR_INVALID_USER_ID));

  /* User 1 Enroll to Profile 1 should be successful */
  enroll_result = user1.Enroll(PROFILE_1);
  EXPECT_REQ(enroll_result,
             Result(FACEAUTH_SUCCESS).SetChallenge(user1.GetAuthID()));
}

TEST_F(FaceAuthTest, EnrollAfterWipeShouldBeSuccessful) {
  User user1(EMBEDDING_VECTOR_1);
  user1.SetEmbeddingVersion(1);

  User user2(EMBEDDING_VECTOR_1);
  user2.SetEmbeddingVersion(1);

  /* Enroll to Profile 1 */
  Result enroll_result = user1.Enroll(PROFILE_1);
  EXPECT_REQ(enroll_result,
             Result(FACEAUTH_SUCCESS).SetChallenge(user1.GetAuthID()));

  /* Profile 1 Authentication should now pass */
  AuthenticateResult auth_result = user1.Authenticate(PROFILE_1);
  EXPECT_AEQ(auth_result, SuccessfulAuthenticateResult(user1));

  ASSERT_TRUE(nugget_tools::WipeUserData(client.get()));

  /* Enroll to Profile 1 */
  enroll_result = user2.Enroll(PROFILE_1);
  EXPECT_REQ(enroll_result,
             Result(FACEAUTH_SUCCESS).SetChallenge(user2.GetAuthID()));

  /* Profile 1 Authentication should now pass */
  auth_result = user2.Authenticate(PROFILE_1);
  EXPECT_AEQ(auth_result, SuccessfulAuthenticateResult(user2));
}

TEST_F(FaceAuthTest, ValidUserIDCheck) {
  User user1(EMBEDDING_VECTOR_1);
  user1.SetEmbeddingVersion(1);

  User user2(EMBEDDING_VECTOR_1);
  user2.SetEmbeddingVersion(1);

  /* User 1 Enroll to Profile 1 */
  Result enroll_result = user1.Enroll(PROFILE_1);
  EXPECT_REQ(enroll_result,
             Result(FACEAUTH_SUCCESS).SetChallenge(user1.GetAuthID()));
  /* Set Feature User ID Check */
  EXPECT_REQ(user1.SetFeature(PROFILE_1, 0), Result(FACEAUTH_SUCCESS));
  EXPECT_REQ(user2.SetFeature(PROFILE_1, 0),
             Result(FACEAUTH_ERR_INVALID_USER_ID));
  /* Clear Feature User ID Check */
  EXPECT_REQ(user1.ClrFeature(PROFILE_1, 0), Result(FACEAUTH_SUCCESS));
  EXPECT_REQ(user2.ClrFeature(PROFILE_1, 0),
             Result(FACEAUTH_ERR_INVALID_USER_ID));
}

TEST_F(FaceAuthTest, EnrollMismatchVersionShouldFail) {
  User user1(EMBEDDING_VECTOR_1);
  user1.SetEmbeddingVersion(1);

  /* Enroll using version 1 to profile 1 */
  Result enroll_result = user1.Enroll(PROFILE_1);
  EXPECT_REQ(enroll_result,
             Result(FACEAUTH_SUCCESS).SetChallenge(user1.GetAuthID()));

  /* Enroll using version 2 to the same profile slot should fail */
  EXPECT_REQ(user1.SetEmbeddingVersion(2).Enroll(PROFILE_1),
             Result(FACEAUTH_ERR_EMBEDDING_VERSION));
}

TEST_F(FaceAuthTest, SFSFullTest) {
  User user1(EMBEDDING_VECTOR_1);
  user1.SetEmbeddingVersion(1);

  /* Enroll to Profile1 20 times */
  for (int i = 0; i < 20; ++i) {
    Result enroll_result = user1.Enroll(PROFILE_1);
    EXPECT_REQ(enroll_result,
               Result(FACEAUTH_SUCCESS).SetChallenge(user1.GetAuthID()));
  }

  /* Enrolling one more time should fail */
  EXPECT_REQ(user1.Enroll(PROFILE_1), Result(FACEAUTH_ERR_SFS_FULL));
}

TEST_F(FaceAuthTest, SimpleMatchMismatchTest) {
  User user1(EMBEDDING_VECTOR_1);
  user1.SetEmbeddingVersion(1);

  /* Profile 1 is empty: authentication will fail */
  EXPECT_REQ(user1.Authenticate(PROFILE_1),
             AuthenticateResult(FACEAUTH_SUCCESS).SetMatch(false));

  /* Enroll to Profile 1 */
  Result enroll_result = user1.Enroll(PROFILE_1);
  EXPECT_REQ(enroll_result,
             Result(FACEAUTH_SUCCESS).SetChallenge(user1.GetAuthID()));

  /* Profile 1 Authentication should now pass */
  AuthenticateResult auth_result = user1.Authenticate(PROFILE_1);
  EXPECT_AEQ(auth_result, SuccessfulAuthenticateResult(user1));

  /* Erase Profile 1*/
  EXPECT_REQ(Device::Erase(PROFILE_1), Result(FACEAUTH_SUCCESS));

  /* Profile 1 is now empty again: authentication should fail */
  EXPECT_REQ(user1.Authenticate(PROFILE_1),
             AuthenticateResult(FACEAUTH_SUCCESS).SetMatch(false));
}

TEST_F(FaceAuthTest, EmbeddingMismatchVersionComparisonShouldError) {
  User user1(EMBEDDING_VECTOR_1);
  user1.SetEmbeddingVersion(1);

  /* Enroll to Profile 1 */
  Result enroll_result = user1.Enroll(PROFILE_1);
  EXPECT_REQ(enroll_result,
             Result(FACEAUTH_SUCCESS).SetChallenge(user1.GetAuthID()));

  /* Upgrade Embedding Version for User 1 */
  user1.SetEmbeddingVersion(2);

  /* Authenticate should now return recalibration error */
  EXPECT_REQ(user1.Authenticate(PROFILE_1), Result(FACEAUTH_ERR_RECALIBRATE));
}

TEST_F(FaceAuthTest, MigrateShouldPreventDowngrade) {
  User user1(EMBEDDING_VECTOR_1);
  user1.SetEmbeddingVersion(5);

  /* User1: enroll to profile 1 */
  Result enroll_result = user1.Enroll(PROFILE_1);
  EXPECT_REQ(enroll_result,
             Result(FACEAUTH_SUCCESS).SetChallenge(user1.GetAuthID()));

  /* User1: authenticate successfully to profile 1 */
  AuthenticateResult auth_result = user1.Authenticate(PROFILE_1);
  EXPECT_AEQ(auth_result, SuccessfulAuthenticateResult(user1));

  /* User1: downgrade and attempt to migrate to profile 3 */
  EXPECT_REQ(user1.SetEmbeddingVersion(4).Migrate(PROFILE_3, 0),
             Result(FACEAUTH_ERR_EMBEDDING_DOWNGRADE));
}

TEST_F(FaceAuthTest, MigrateShouldPreventMismatchVersion) {
  User user1(EMBEDDING_VECTOR_1);
  user1.SetEmbeddingVersion(5);

  /* User1: enroll to profile 1 */
  Result enroll_result = user1.Enroll(PROFILE_1);
  EXPECT_REQ(enroll_result,
             Result(FACEAUTH_SUCCESS).SetChallenge(user1.GetAuthID()));

  /* User1: authenticate successfully to profile 1 */
  AuthenticateResult auth_result = user1.Authenticate(PROFILE_1);
  EXPECT_AEQ(auth_result, SuccessfulAuthenticateResult(user1));

  /* User1: upgrade and migrate to profile 3 */
  EXPECT_REQ(user1.SetEmbeddingVersion(6).Migrate(PROFILE_3, 1),
             MigrateResult(FACEAUTH_SUCCESS).SetEmbeddingNum(1).SetMatch(true));
  EXPECT_REQ(user1.SetEmbeddingVersion(7).Migrate(PROFILE_3, 0),
             Result(FACEAUTH_ERR_EMBEDDING_VERSION));
}

TEST_F(FaceAuthTest, MigrateShouldCopyUserInfo) {
  User user1(EMBEDDING_VECTOR_1);
  user1.SetEmbeddingVersion(5);

  /* User1: enroll to profile 1 */
  Result enroll_result = user1.Enroll(PROFILE_1);
  EXPECT_REQ(enroll_result,
             Result(FACEAUTH_SUCCESS).SetChallenge(user1.GetAuthID()));

  /* User1: set feature */
  EXPECT_REQ(user1.SetFeature(PROFILE_1, 0xFACEDEAD), Result(FACEAUTH_SUCCESS));

  /* User1: authenticate successfully to profile 1 */
  AuthenticateResult auth_result = user1.Authenticate(PROFILE_1);
  EXPECT_AEQ(auth_result, SuccessfulAuthenticateResult(user1));

  /* User1: migrate to profile 3 */
  EXPECT_REQ(user1.SetEmbeddingVersion(8).Migrate(PROFILE_3, 1),
             MigrateResult(FACEAUTH_SUCCESS).SetEmbeddingNum(1).SetMatch(true));

  EXPECT_EQ(0xFACEDEAD, user1.GetFeature(PROFILE_3));

  /* User1: authenticate successfully using profile 3 */
  auth_result = user1.Authenticate(PROFILE_3);
  EXPECT_AEQ(auth_result, SuccessfulAuthenticateResult(user1));
}

TEST_F(FaceAuthTest, SimpleAuthenticateMigrateFlow) {
  User user1(EMBEDDING_VECTOR_1);
  user1.SetEmbeddingVersion(1);

  User user2(EMBEDDING_VECTOR_1);
  user2.SetEmbeddingVersion(1);

  /* User1: enroll to profile 1 */
  Result enroll_result = user1.Enroll(PROFILE_1);
  EXPECT_REQ(enroll_result,
             Result(FACEAUTH_SUCCESS).SetChallenge(user1.GetAuthID()));

  /* User2: enroll to profile 2 */
  enroll_result = user2.Enroll(PROFILE_2);
  EXPECT_REQ(enroll_result,
             Result(FACEAUTH_SUCCESS).SetChallenge(user2.GetAuthID()));

  /* User1: authenticate successfully to profile 1 */
  AuthenticateResult auth_result = user1.Authenticate(PROFILE_1);
  EXPECT_AEQ(auth_result, SuccessfulAuthenticateResult(user1));

  /* User1: migrate to profile 3 */
  EXPECT_REQ(user1.Migrate(PROFILE_3, 0), MigrateResult(FACEAUTH_SUCCESS));

  /* User2: authenticate successfully to profile 2 */
  auth_result = user2.Authenticate(PROFILE_2);
  EXPECT_AEQ(auth_result, SuccessfulAuthenticateResult(user2));

  /* User2: migrate to profile 3 should fail */
  EXPECT_REQ(user2.Migrate(PROFILE_3, 0),
             MigrateResult(FACEAUTH_ERR_INVALID_USER_ID));

  /* User2: migrate to profile 4 */
  EXPECT_REQ(user2.Migrate(PROFILE_4, 1),
             MigrateResult(FACEAUTH_SUCCESS).SetEmbeddingNum(1).SetMatch(true));
  EXPECT_REQ(user2.Migrate(PROFILE_4, 1),
             MigrateResult(FACEAUTH_SUCCESS).SetEmbeddingNum(2).SetMatch(true));
}

TEST_F(FaceAuthTest, FiveAuthenticationFailureSequenceTest) {
  User user1(EMBEDDING_VECTOR_1);
  user1.SetEmbeddingVersion(1);

  User user2(EMBEDDING_VECTOR_NULL);
  user2.SetEmbeddingVersion(1);

  /* Enroll to Profile 1 */
  Result enroll_result = user1.Enroll(PROFILE_1);
  EXPECT_REQ(enroll_result,
             Result(FACEAUTH_SUCCESS).SetChallenge(user1.GetAuthID()));

  /* Fail Authentication 4 times */
  for (int i = 0; i < 4; ++i) {
    EXPECT_REQ(user2.Authenticate(PROFILE_1),
               AuthenticateResult(FACEAUTH_SUCCESS).SetMatch(false));
  }

  /* Fifth Authentication failure should trigger lockout event */
  EXPECT_REQ(user2.Authenticate(PROFILE_1),
             AuthenticateResult(FACEAUTH_SUCCESS)
                 .SetMatch(false)
                 .SetLockoutEvent(FACEAUTH_LOCKOUT_ENFORCED));

  /* User will be throttled for 30 seconds */
  Result result = user2.GetUserInfo(PROFILE_1);
  EXPECT_GE(result.GetSecond(), 25);
  EXPECT_REQ(
      result,
      Result(FACEAUTH_SUCCESS).SetSecond(result.GetSecond()).SetThird(1));

  /* Following Authentication attempt will be throttled */
  EXPECT_REQ(user2.Authenticate(PROFILE_1),
             AuthenticateResult(FACEAUTH_ERR_THROTTLE));

  /* Reset Lockout should trigger lockout event */
  EXPECT_REQ(user1.ResetLockout(PROFILE_1),
             ResetLockoutResult(FACEAUTH_SUCCESS)
                 .SetLockoutEvent(FACEAUTH_LOCKOUT_REMOVED));
}

TEST_F(FaceAuthTest, ExhaustiveLockoutTest) {
  vector<User> users;

  for (int i = 0; i < MAX_NUM_PROFILES; ++i) {
    users.push_back(User(EMBEDDING_VECTOR_1).SetEmbeddingVersion(1));
    Result enroll_result = users[i].Enroll(i + 1);
    EXPECT_REQ(enroll_result,
               Result(FACEAUTH_SUCCESS).SetChallenge(users[i].GetAuthID()));
    EXPECT_EQ(users[i].IsProfileLocked(i + 1), false);
  }

  bool lock_test_vectors[6] = {true, false, false, false, true, true};
  for (int i = 0; i < MAX_NUM_PROFILES; ++i) {
    if (lock_test_vectors[i]) {
      users[i].LockProfile(i + 1);
    }
  }

  for (int i = 0; i < MAX_NUM_PROFILES; ++i) {
    EXPECT_EQ(users[i].IsProfileLocked(i + 1), lock_test_vectors[i]);
  }

  bool unlock_test_vectors[6] = {true, false, false, false, true, false};
  for (int i = 0; i < MAX_NUM_PROFILES; ++i) {
    if (unlock_test_vectors[i]) {
      users[i].ResetLockout(i + 1);
    }
  }

  for (int i = 0; i < MAX_NUM_PROFILES; ++i) {
    EXPECT_EQ(users[i].IsProfileLocked(i + 1),
              lock_test_vectors[i] && !unlock_test_vectors[i]);
  }
}

TEST_F(FaceAuthTest, ExhaustiveFeatureTest) {
  vector<User> users;

  uint32_t feature_msk[MAX_NUM_PROFILES] = {0};
  for (int i = 0; i < MAX_NUM_PROFILES; ++i) {
    users.push_back(User(EMBEDDING_VECTOR_NULL).SetEmbeddingVersion(1));
    Result enroll_result = users[i].Enroll(i + 1);
    EXPECT_REQ(enroll_result,
               Result(FACEAUTH_SUCCESS).SetChallenge(users[i].GetAuthID()));
  }

  uint32_t index = 0;
  for (int k = 0; k < 5; ++k) {
    for (int i = 0; i < MAX_NUM_PROFILES; ++i)
      EXPECT_EQ(users[i].GetFeature(i + 1), feature_msk[i]);

    for (int i = 0; i < MAX_NUM_PROFILES; ++i) {
      EXPECT_REQ(users[i].SetFeature(i + 1, 1 << index),
                 Result(FACEAUTH_SUCCESS));
      feature_msk[i] |= (1 << index);
      index++;
    }
  }

  index = 0;
  for (int k = 0; k < 5; ++k) {
    for (int i = 0; i < MAX_NUM_PROFILES; ++i)
      EXPECT_EQ(users[i].GetFeature(i + 1), feature_msk[i]);

    for (int i = 0; i < MAX_NUM_PROFILES; ++i) {
      EXPECT_REQ(users[i].ClrFeature(i + 1, 1 << index),
                 Result(FACEAUTH_SUCCESS));
      feature_msk[i] &= ~(1 << index);
      index++;
    }
  }
}

static void FullMatchMismatchTest(uint32_t profile_1, uint32_t profile_2) {
  User user1(EMBEDDING_VECTOR_1);
  user1.SetEmbeddingVersion(1);

  User user2(EMBEDDING_VECTOR_NULL);
  user2.SetEmbeddingVersion(1);

  for (uint32_t i = 0; i < 20; ++i) {
    Result result;
    result = user1.SetEmbeddingBase(EMBEDDING_VECTOR_1).Enroll(profile_1);
    EXPECT_REQ(result,
               Result(FACEAUTH_SUCCESS).SetChallenge(user1.GetAuthID()));

    result = user2.SetEmbeddingBase(EMBEDDING_VECTOR_2).Enroll(profile_2);
    EXPECT_REQ(result,
               Result(FACEAUTH_SUCCESS).SetChallenge(user2.GetAuthID()));
  }

  user1.SetEmbeddingBase(EMBEDDING_VECTOR_1);
  user2.SetEmbeddingBase(EMBEDDING_VECTOR_2);

  AuthenticateResult auth_result = user1.Authenticate(profile_1);
  EXPECT_AEQ(auth_result, SuccessfulAuthenticateResult(user1));
  auth_result = user2.Authenticate(profile_1);
  EXPECT_REQ(auth_result, AuthenticateResult(FACEAUTH_SUCCESS).SetMatch(false));
  auth_result = user1.Authenticate(profile_2);
  EXPECT_REQ(auth_result, AuthenticateResult(FACEAUTH_SUCCESS).SetMatch(false));
  auth_result = user2.Authenticate(profile_2);
  EXPECT_AEQ(auth_result, SuccessfulAuthenticateResult(user2));
}

TEST_F(FaceAuthTest, ExhaustiveMatchMismatchTest) {
  FullMatchMismatchTest(PROFILE_1, PROFILE_6);
  FullMatchMismatchTest(PROFILE_2, PROFILE_5);
  FullMatchMismatchTest(PROFILE_3, PROFILE_4);
}
}

