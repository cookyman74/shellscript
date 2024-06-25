#!/bin/bash

# test_script.sh

# 함수: 진행 상황 출력
progress() {
    echo "Progress: $1"
    sleep 1
}

# 함수: 로그 메시지 출력
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    sleep 0.5
}

# 메인 설치 프로세스 시뮬레이션
log_message "설치 프로세스 시작"

progress 0

log_message "시스템 확인 중..."
progress 10

log_message "필요한 패키지 다운로드 중..."
progress 20

log_message "데이터베이스 설정 중..."
progress 30

log_message "서비스 구성 중..."
progress 50

log_message "설정 파일 생성 중..."
progress 70

log_message "서비스 시작 중..."
progress 90

log_message "최종 점검 중..."
progress 100

log_message "설치 완료!"

# 오류 시뮬레이션 (주석 처리된 상태)
# log_message "오류: 데이터베이스 연결 실패"
# exit 1

exit 0