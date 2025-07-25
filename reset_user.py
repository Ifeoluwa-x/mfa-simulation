from app import app, db, User, LoginLog
import pyotp

def reset_users():
    with app.app_context():
        # Delete all login logs
        LoginLog.query.delete()
        # Delete all users
        User.query.delete()
        db.session.commit()
        print("✅ All users and login logs deleted.")

        # Create test user fresh
        secret = pyotp.random_base32()
        username = "test"
        password = "test123."
        test_user = User(
            username=username,
            password=password,
            email="test@gmail.com",
            secret=secret,
            is_verified=False
        )
        db.session.add(test_user)
        db.session.commit()
        print(f"✅ Test user created: {username} / {password} (secret: {secret})")
        print("✅ Database reset complete.")

if __name__ == "__main__":
    reset_users()
