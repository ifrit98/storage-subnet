import os
import redis
import unittest
from passlib.context import CryptContext
from database import get_database, startup, UserInDB, create_user, get_user

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

UNUSED_DB = 15  # WARNING: This will clear the entire Redis database. Use with caution.
PORT = 6379
HOST="localhost"

os.environ["REDIS_HOST"] = HOST
os.environ["REDIS_PORT"] = str(PORT)
os.environ["REDIS_DB"]   = str(UNUSED_DB)

startup()
redis_db = get_database()

class UserRedisTestCase(unittest.TestCase):
    def setUp(self):
        redis_db.flushdb()

    def tearDown(self):
        redis_db.flushdb()

    def test_user_creation_and_retrieval(self):
        fake_user = UserInDB(
            username="janedoe",
            hashed_password=pwd_context.hash("password123"),
            seed="b6825ec6168f72e90b1244b1d2307433ad8394ad65b7ef4af10966bc103a39bf",
            wallet_name="janedoe",
            wallet_hotkey="default",
            wallet_mnemonic="ocean bean until sauce near place labor admit dismiss long asthma tunnel"
        )
        create_user(fake_user)

        # Retrieve the user
        retrieved_user = get_user("janedoe")

        # Assert equality
        self.assertIsNotNone(retrieved_user)
        self.assertEqual(fake_user.username, retrieved_user.username)
        self.assertEqual(fake_user.hashed_password, retrieved_user.hashed_password)
        self.assertEqual(fake_user.seed, retrieved_user.seed)
        self.assertEqual(fake_user.wallet_name, retrieved_user.wallet_name)
        self.assertEqual(fake_user.wallet_hotkey, retrieved_user.wallet_hotkey)
        self.assertEqual(fake_user.wallet_mnemonic, retrieved_user.wallet_mnemonic)
