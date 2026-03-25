from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

# 상대 경로 임포트
from ...database import get_db
from ... import models, schemas
from . import service  # 같은 폴더의 service.py 사용

router = APIRouter(
    prefix="/api/v1/auth",
    tags=["인증(Authentication)"]
)

@router.post("/login")
def login(response: Response, login_data: schemas.LoginRequest, db: Session = Depends(get_db)):
    # 1. 사용자 확인
    user = db.query(models.User).filter(models.User.username == login_data.username).first()
    
    # 2. 비밀번호 검증 (service의 함수 사용)
    if not user or not service.verify_password(login_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="아이디 또는 비밀번호가 잘못되었습니다."
        )
    
    # 3. 토큰 생성
    access_token = service.create_access_token(
        data={"sub": user.username, "role": user.role.role_name}
    )

    # 4. 쿠키 설정
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=3600 * 24,
        samesite="lax",
        secure=False # HTTPS 환경에서는 True로 변경 필수
    )
    
    return {
        "username": user.username, 
        "full_name": user.full_name, 
        "role": user.role.role_name
    }

@router.post("/logout")
def logout(response: Response):
    response.delete_cookie("access_token")
    return {"message": "로그아웃 성공"}