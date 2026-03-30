import bcrypt
from sqlalchemy.orm import Session
from .models import DetectionRule, User, Role
from .database import SessionLocal, engine, Base


def get_password_hash(password: str) -> str:
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode('utf-8')


def seed_db():
    if not engine or not SessionLocal:
        print("⚠️ DB 없음 → seed 실행 스킵")
        return

    print("⏳ DB 초기화 중...")

    try:
        Base.metadata.create_all(bind=engine)
    except Exception as e:
        print("⚠️ create_all 실패:", e)
        return

    db: Session = SessionLocal()

    try:
        admin_role = db.query(Role).filter(Role.role_name == "admin").first()
        if not admin_role:
            admin_role = Role(role_name="admin", description="전체 관리자")
            db.add(admin_role)
            db.commit()
            db.refresh(admin_role)

        if not db.query(User).filter(User.username == "admin").first():
            admin_user = User(
                username="admin",
                password_hash=get_password_hash("admin123!"),
                full_name="관리자",
                role_id=admin_role.id,
                email="admin@example.com"
            )
            db.add(admin_user)
            db.commit()

        print("✅ DB 초기화 완료")

    except Exception as e:
        print(f"❌ 오류 발생: {e}")
        db.rollback()
    finally:
        db.close()


if __name__ == "__main__":
    seed_db()
