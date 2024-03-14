#!/bin/bash -x

####################################################################
# Subject : Check list for SAMW's Security                         #
# Date : 2010.09.17                                                #
# author : Jung-Ho Jang.                                           #
# Verion  : 1.0.0                                                  #
####################################################################



. /etc/rc.d/init.d/functions
quote=$'\042'

LANG="ko_KR."
SUPPORTED="en_US.iso885915:en_US:en:ko_KR.eucKR:ko_KR:ko"
SYSFONT="lat0-sun16"
SYSFONTACM="iso15"

export LANG
export SUPPORTED
export SYSFONT

HOSTNAME=`hostname`
CheckResultFileName='CheckResult.txt'

[[ -d ${HOSTNAME} ]] || mkdir ${HOSTNAME}
[[ -f ${HOSTNAME}/${CheckResultFileName} ]] && cat /dev/null > ${HOSTNAME}/${CheckResultFileName}

######################################
############# 기본 설정  #############
######################################

PASSWD="/etc/passwd"				#### 패스워드 파일 위치 ####
SHADOW="/etc/shadow"				#### 쉐도우 파일 위치 ####
PASSWD_CONF="/etc/login.defs"		#### 패스워드 정책 설정 파일 위치 ####
SSH_CONF="/etc/ssh/sshd_config"		#### 로그인 설정 파일 위치 ####
LOGIN_CONF="/etc/pam.d/login"		#### 로그인 설정 파일 위치 ####
HOSTS_ALLOW="/etc/hosts.allow"		#### 허용 호스트 목록 ####
HOSTS_DENY="/etc/hosts.deny"		#### 거부 호스트 목록 ####
HOSTS="/etc/hosts"				#### hosts 파일 위치 ####
CRON_DENY="/etc/cron.deny"		#### cron.deny 파일 위치 ####
GROUP="/etc/group"				#### group 파일 위치 ####
SERVICES="/etc/services"			#### services 파일 위치 ####
BANNER="/etc/issue"				#### 배너설정 ####
SMTP_CONF="/etc/mail/sendmail.cf"		#### 센드메일 설정 파일 ####
SNMP_CONF="/etc/snmp/conf/snmpd.conf"	#### SNMP 설정 파일 ####
SYSLOG_CONF="/etc/syslog.conf"		#### SYSLOG 설정 파일 ####
SECURE_LOG="/var/log/secure"		#### Secure log 설정 파일 ####

[[ -f ${PASSWD} ]] || echo "${PASSWD} file is not exist"
[[ -f ${SHADOW} ]] || echo "${SHADOW} file is not exist"
[[ -f ${PASSWD_CONF} ]] || echo "${PASSWD_CONF} file is not exist"
[[ -f ${SSH_CONF} ]] || echo "${SSH_CONF} file is not exist"
[[ -f ${LOGIN_CONF} ]] || echo "${LOGIN_CONF} file is not exist"
[[ -f ${HOSTS_ALLOW} ]] || echo "${HOSTS_ALLOW} file is not exist"
[[ -f ${HOSTS_DENY} ]] || echo "${HOSTS_DENY} file is not exist"
[[ -f ${HOSTS} ]] || echo "${HOSTS} file is not exist"
[[ -f ${CRON_DENY} ]] || echo "${CRON_DENY} file is not exist"
[[ -f ${GROUP} ]] || echo "${GROUP} file is not exist"
[[ -f ${SERVICES} ]] || echo "${SERVICES} file is not exist"
[[ -f ${BANNER} ]] || echo "${BANNER} file is not exist"
[[ -f ${SMTP_CONF} ]] || echo "${SMTP_CONF} file is not exist"
[[ -f ${SNMP_CONF} ]] || echo "${SNMP_CONF} file is not exist"
[[ -f ${SYSLOG_CONF} ]] || echo "${SYSLOG_CONF} file is not exist"
[[ -f ${SECURE_LOG} ]] || echo "${SECURE_LOG} file is not exist"

echo "***************************************************************************"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "*                                                                         *"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "*            Jung-Ho Consulting for SAMW SEcure CheckList                 *"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "*                                                                         *"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "*    Copyright 2010 Snapthinking Co. Ltd. All right Reserved              *"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "*                                                                         *"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "***************************************************************************"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME/$HOSTNAME.txt 2>&1

echo "* Start Time:" `date`			>> $HOSTNAME/$HOSTNAME.txt 2>&1



CommandTest(){
  # 명령어 테스트 (성공/실패)
  # 인수값은 성공/실패에 대한 출력문
  if [ "$?" == "0" ] ; then
    echo -n $"${1} ...: "
    success
	echo "${1} ...: 완료" >> ${PATCHLOG}
    echo ""
  else
    echo -n $"${1} ...: "
    failure
	echo "${1} ...: 실패" >> ${PATCHLOG}
    echo ""
    exit 0;
  fi
}

MAX=90 # 보고서 양식 문자수
setline() {
#parameter1 : 종류
#parameter2 : 문자개수
    count=${2}
    for (( a=1 ; a<$count ; a++ ))
    do
      echo -n "${1}"
    done
}


Subject1(){
# 영문만..
  num=`echo "$1" | wc -m`
  let "MIN=($MAX-$num)/2"

  echo "" >> ${HOSTNAME}/CheckResultList.txt
  setline '#' ${MIN} >> ${HOSTNAME}/CheckResultList.txt
  echo -n " ${1} " >> ${HOSTNAME}/CheckResultList.txt
  setline '#' ${MIN} >> ${HOSTNAME}/CheckResultList.txt
  echo "" >> ${HOSTNAME}/CheckResultList.txt
}

Subject2(){
  num=`echo "$1" | wc -m`
  let "MIN=($MAX-$num)/2"

  echo "" >> ${HOSTNAME}/CheckResultList.txt
  setline '*' ${MIN} >> ${HOSTNAME}/CheckResultList.txt
  echo -n " ${1} "  >> ${HOSTNAME}/CheckResultList.txt
  setline '*' ${MIN} >> ${HOSTNAME}/CheckResultList.txt
  echo "" >> ${HOSTNAME}/CheckResultList.txt
  setline "*" ${MAX} >> ${HOSTNAME}/CheckResultList.txt
  echo "" >> ${HOSTNAME}/CheckResultList.txt
}

checkSubject() {
  num=`echo "--- $1" | wc -m`
  let "MIN=$MAX-$num"

  echo "" >> ${HOSTNAME}/CheckResultList.txt
  echo -n "--- ${1}" >> ${HOSTNAME}/CheckResultList.txt
  setline '-' ${MIN} >> ${HOSTNAME}/CheckResultList.txt
  echo "" >> ${HOSTNAME}/CheckResultList.txt
}

endLine(){
case ${1} in
  "mainend")
    setline "#" $MAX >> ${HOSTNAME}/CheckResultList.txt
  ;;
  "subend")
    setline "-" $MAX >> ${HOSTNAME}/CheckResultList.txt
  ;;
  "checkend")
    setline "." $MAX >> ${HOSTNAME}/CheckResultList.txt
  ;;
esac
}

checkResult() {
 eval $1 >> ${HOSTNAME}/CheckResultList.txt
 echo "" >> ${HOSTNAME}/CheckResultList.txt
}






report_print(){
# parameter1 : 분류(대제목,소제목 등 옵션)
# parameter2 : 제목 예: "1. 계정 및 패스워드 관리"
# Parameter3 : 결과값 또는 명령실행 문

case ${1} in
"1") ## 대항목
  Subject1 "${2}"
;;

"2") ## 대분류 번호
  Subject2 "${2}"
;;

"3") ## 세부 점검 리스트
  checkSubject "${2}"
  checkResult "${3}"
  if [ -n $3 ] ; then
    endLine checkend
  fi
;;

"4") ## 괄호 목차
  echo "${2}">>${HOSTNAME}/CheckResultList.txt
  checkResult "${3}"
  endLine checkend
;;

"*") ## Consulting
  echo "${2}">>${HOSTNAME}/CheckResultList.txt
  echo "">>${HOSTNAME}/CheckResultList.txt
  endLine checkend
;;
esac
}


echo -n "Start to Check: ">>${HOSTNAME}/CheckResultList.txt
checkResult `date`

Subject1 " System Information Query Start "

Subject2 "Network Interface Status"
checkResult "/sbin/ifconfig -a"

report_print "Network Interface Status"	3 "`/sbin/ifconfig -a`"
report_print "Network Session Port List" 3 "`/usr/sbin/lsof | grep LISTEN`"

report_print "Linux OS Version" 3 "`/bin/uname -a | awk '{print $1,$3}'`"
report_print "OS bit" 4 "`/usr/bin/getconf LONG_BIT`"

report_print "### 실행중인 프로세스 및 데몬점검.(프로세스의 생성관계) ###" 2 "`/usr/bin/prstree`"
report_print "### 계정별 최후접속 기록 ###"	2 "`/usr/bin/lastlog`"



Root_ID_Check(){

MainSubject="1. 계정 및 패스워드 관리"
report_print ${MainSubject} 2

CheckList_101="3W_101. root 이외에 UID/GID가 0인 사용자가 존재하지 않는가?"
report_print ${CheckList_101} 3

Clist1="(1) US101-1. UID가 0인 사용자"
report_print ${Clist1} 4 "`awk -F: '($3 == "0") {print $1}' $PASSWD`"

Clist2="(2) US101-2. GID가 0인 사용자"
report_print ${Clist2} 4 "`awk -F: '($3 == "0") {print $1}' $PASSWD`"

Consult='
@권고사항
- 일반적으로 100보다 작은 UID들과 010보다 작은 GID들은 시스템 계정을 위해 사용됨.
- 따라서 점검목록을 통해 불필요한 계정은 삭제할 것을 권고'
report_print ${Consult} 5
}







####################################################################################################################################
####################################################################################################################################



echo '
-----US102. 불필요하게 부여된 쉘과 계정이 존재하지 않는가?--------------------------------------------'	>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo '
(1) 쉘이 부여된 계정'										>> $HOSTNAME/$HOSTNAME.txt 2>&1
	cat $PASSWD | awk -F: '{print $1, $7}' | egrep "bash|csh|born|tsh|ksh|zsh|sh$"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo '
(2) 쉘이 없거나 /bin/false 인 계정'								>> $HOSTNAME/$HOSTNAME.txt 2>&1
	cat $PASSWD | awk -F: '{print $1, $7}' | egrep -v "bash|csh|born|tsh|ksh|zsh|sh$"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo '
@권고사항
daemon, bin, lp, rpm, amanda, netdump, pvm, uucp 등은 불필요한 계정
sys, bin, lp, uucp, nuucp, www, mysql, nobody 등은 쉘이 불필요한 계정(공란 or /bin/false)'	>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "."												>> $HOSTNAME/$HOSTNAME.txt 2>&1

## (1) 불필요한 시스템계정 자동 삭제 스크립트 생성
	echo -e '# 사용할 필요가 없는 계정 삭제
for LIST in `cat /etc/passwd | awk -F: \047{print $1}\047`
do
  if echo $LIST | egrep "daemon|bin|lp|rpm|amanda|netdump|pvm|uucp" > /dev/null
  then
    echo "$LIST 계정을 삭제하시겠습니까?"
    select VAL in "yes" "no"
    do
      break
    done
    if [ "$VAL" == "yes" ];
    then
      echo "you select "$VAL""
      /sbin/userdel $LIST
    else
      echo "$LIST resever"
    fi
   fi
done'					>> $HOSTNAME/PatchScript.sh 2>&1
	echo " "			>> $HOSTNAME/PatchScript.sh 2>&1

## (2) 쉘사용이 불필요한 계정에 대한 자동 환경설정 스크립트 생성
	echo -e '# 쉘환경이 불필요한 계정 삭제
for LIST in `cat /etc/passwd | egrep "sys|^bin|lp|uucp|nuucp|www|mysql|nobody" | awk -F: \047{print $1}\047`
do
  echo "$LIST"
  sed -i "/^$LIST/s/\/bin\/[tzcj]sh/\/sbin\/nologin/" -i "/^$LIST/s/\/bin\/bash/\/sbin\/nologin/" /etc/passwd
done'					>> $HOSTNAME/PatchScript.sh 2>&1
	echo " "			>> $HOSTNAME/PatchScript.sh 2>&1

echo '
-----US104. 패스워드 복잡도를 설정 하였는가?--------------------------------------------

(1) pam 설정 현황'									>> $HOSTNAME/$HOSTNAME.txt 2>&1
	cat /etc/pam.d/system-auth-ac | egrep "^password"			>> $HOSTNAME/$HOSTNAME.txt 2>&1

echo '
(2) 패스워드 복잡도 설정(/etc/pam.d/system-auth-ac파일의 pam_cracklib.so 인수값)
- retry=N : 패스워드 입력 실패 시 재시도횟수
- difok=N : 기존 패스워드와 비교. 기본값10 (50%)
- minlen=N :  크레디트를 더한 패스워드최소길이
- dcredit=N : 숫자에 주어지는 크레디트값. 기본 1
- udredit=N : 영어대문자에 주어지는 크레디트값
- lcredit=N : 영어 소문자에 주어지는 크레디트값
- ocredit=N : 숫자, 영어대/소문자를 제외한 기타문자
- use_authok : 기존 패스워드를 다시 사용

@권고사항
- 패스워드는 최소 8자로 한다.
- 패스워드는 적어도 하나의 소문자를 포함한다.
- 패스워드는 적어도 하나의 대문자를 포함한다.
- 패스워드는 적어도 하나의 숫자를 포함한다.
- 패스워드는 적어도 하나의 서로 다른 문자를 포함한다
- 이전 비밀번호와 새로운 비밀번호는 2자 이상이 달라야 한다
- 최근 15개의 비밀번호는 재사용할 수 없어야 한다.
- 5번 이상의 로그인 시도에서 실패하게되면, 해당 계정을 사용할 수 없도록 한다.

-- 예시 --
auth required /lib/security/pam_env.so
auth required /lib/security/pam_tally.so onerr=fail no_magic_root
auth sufficient /lib/security/pam_unix.so likeauth nullok
auth required /lib/security/pam_deny.so

account required /lib/security/pam_unix.so
account required /lib/security/pam_tally.so deny=5 no_magic_root reset

password required /lib/security/pam_cracklib.so retry=3 minlen=8 lcredit=-1 ucredit=-1 dcredit=-1 ocredit=-1 difok=2
password sufficient /lib/security/pam_unix.so nullok use_authtok md5 shadow remember=15
password required /lib/security/pam_deny.so

session required /lib/security/pam_limits.so
session required /lib/security/pam_unix.so'					>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo '.'										>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo '
-----US105. secure로그에 bruteforce attack이 감지되었는가? ----------------------------
'											>> $HOSTNAME/$HOSTNAME.txt 2>&1
	COUNT=0;
	LIST=`grep "Failed password for" $SECURE_LOG | egrep -v "invalid user|{USERID}|{LOGINIP}" | awk '{ print $11}'`
	if [ -n "$LIST" ]
	then
	  for HOST in $LIST
	  do
   	    let "COUNT=$COUNT+1"
  	  done
  	echo "$HOST is Failed Password : $COUNT"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	fi

	COUNT=0;
	LIST=`grep "Failed password for invalid user" $SECURE_LOG | awk '{ print $13}'`
	if [ -n "$LIST" ]
	then
  	  for HOST in $LIST
	  do
  	    let "COUNT=$COUNT+1"
  	  done
  	  echo "$HOST is Failed Password for invalid user : $COUNT"		>> $HOSTNAME/$HOSTNAME.txt 2>&1
	fi

	COUNT=0;
	LIST=`grep "vsftpd:auth): authentication failure" $SECURE_LOG | egrep -v "{USERID}|{LOGINIP}" | awk '{ print $14}'`
	if [ -n "$LIST" ]
	then
	  for HOST in $LIST
	    do
	    let "COUNT=$COUNT+1"
	  done
	echo "$FLIST is authentication failure(vsftpd) : $COUNT"		>> $HOSTNAME/$HOSTNAME.txt 2>&1
	fi
echo "."										>> $HOSTNAME/$HOSTNAME.txt 2>&1

echo '
-----US107. OpenSSH의 보안설정 설정하였는가? ----------------------------------------
'											>> $HOSTNAME/$HOSTNAME.txt 2>&1
	if cat $SSH_CONF | grep "^Protocol 2" > /dev/null
	then echo "(1) Protocol 2 설정: Good"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else echo "(1) Protocol 2으로 변경 필요"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	fi

	SSH_PORT=`cat $SSH_CONF | grep "^Port" | awk '{print $2}'`
	if [ -z "$SSH_PORT" ];
	then echo "(2) ssh port 변경설정 필요"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  if [ $SSH_PORT = 22 ];
	  then echo "(2) ssh port 변경설정 필요"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  else echo "(2) ssh port : $SSH_PORT"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  fi
	fi

	if cat $SSH_CONF | grep "^PermitRootLogin no" > /dev/null
	then echo "(3) 루트 로그인 불가 설정 : Good"				>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else echo "(3) 루트 로그인 불가 설정 필요 : 'PermitRootLogin no' 설정">> $HOSTNAME/$HOSTNAME.txt 2>&1
	fi

	if cat $SSH_CONF | grep "^MaxAuthTries" > /dev/null
	then echo "(4) 로그인 시도횟수 : `cat $SSH_CONF | grep ^MaxAuthTries | awk '{print$2}'`"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else echo "(4) 로그인 시도횟수 설정 필요 : 'MaxAuthTries 횟수' 설정"				>> $HOSTNAME/$HOSTNAME.txt 2>&1
	fi

	if cat $SSH_CONF | grep "^AllowGroups wheel" > /dev/null
	then echo "(5) wheel그룹으로 로그인 제한 : Good"				>> $HOSTNAME/$HOSTNAME.txt 2>&1
		cat /etc/group|grep wheel|cut -f4 -d":"|sed "s/^/wheel 그룹: /">> $HOSTNAME/$HOSTNAME.txt 2>&1
	else echo "(5) 로그인 제한 설정 필요 : 'AllowGroups wheel' 설정"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	fi

	if cat $SSH_CONF | grep "^RhostsAuthentication no" > /dev/null
	then echo "(6) SSH의 'rhost'인증 차단설정 : Good " 					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else echo "(6) SSH의 'rhost'인증 차단설정 필요 : 'RhostsAuthentication no' 설정"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	fi

	if cat $SSH_CONF | grep "^PermitEmptyPasswords no" > /dev/null
	then echo "(7) 패스워드 인증 설정 : Good"						>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else echo "(7) 패스워드 인증 설정 필요 : 'PermitEmptyPasswords no' 설정"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	fi

echo '
@권고사항
(1) 보안상 Protocol 2을 사용할 것을 권장
(2) 포트는 기본 포트(22) 대신 다른 포트를 사용할 것을 권장
(3) 원격에서는 루트로 로그인하지 못하도록 제한할 것을 권장
(4) 원격 로그인은 wheel그룹으로 제한할 것을 권장
(5) .rhost는 보안상 매우 위험하므로 사용하지 말것을 권장
(6) 암호 없이 로그인하도록 하는 것은 보안상 매우 위험'				>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo '.'										>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo '
-----US109. root의 History 개수 확인 ----------------------------------------
'											>> $HOSTNAME/$HOSTNAME.txt 2>&1
	cat /root/.bash_history | wc -l						>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo '
@참고사항
- History 개수가 보통 1000라인 이상되어야 한다.
- 만약 그 이하라면 침입 여부를 재 확인해봐야 한다.'				>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "."										>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo " "										>> $HOSTNAME/$HOSTNAME.txt 2>&1






####################################################################################################################################
####################################################################################################################################
echo '
******************************* 2. 접근제어 *********************************************
*****************************************************************************************

-----US201. 인가된 시스템에서만 접근이 가능하도록 설정하였는가?--------------------------'	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	if chkconfig --list | grep iptables | grep 3:활성 > /dev/null
	then
	  echo '
	  (1) iptables 서비스 자동실행 여부 : OK
	  (2) 등록된 iptables 정책 확인'				>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  /sbin/iptables -L --line -nv				>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo '
	  (1) iptables 서비스 자동실행 여부 : NO
	  (2) 등록된 iptables 정책 확인'				>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  /sbin/iptables -L --line -nv				>> $HOSTNAME/$HOSTNAME.txt 2>&1
	fi
	echo " "							>> $HOSTNAME/$HOSTNAME.txt 2>&1
	echo "(3) R-Command관련 설정 파일"				>> $HOSTNAME/$HOSTNAME.txt 2>&1
	echo "검색된 .rhost 파일의 삭제"				>> $HOSTNAME/PatchScript.sh 2>&1
## (3) .rhost 파일 자동 삭제 쉘 스크립트 생성
	for LIST in `find / -name .rhosts -exec ls {} \;`
	do
	  echo "- $LIST 파일"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  echo "===파일내용====================================================================="	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  cat $LIST												>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  echo "---------------------------------------------------------------------------끝---"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  echo "$LIST 파일을 삭제하시겠습니까?"								>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "
	  select VAL in "yes" "no"
	  do
	    break
	  done
	  if [ "$VAL" == "yes" ];
	  then
	    you select "$VAL"
	    rm -rf $LIST
	    $LIST 파일이 삭제되었습니다.
	  else
	    $LIST 파일이 보존되었습니다.
	  fi"						>> $HOSTNAME/PatchScript.sh 2>&1
	done
	echo " "					>> $HOSTNAME/PatchScript.sh 2>&1
echo '
@권고사항
(1) 방화벽 iptables은 기본적으로 서비스에 등록하여 자동실행되도록 설정한다.

(2) 방화벽 정책은 기본적으로 "명백히 금지되지 않은 것은 허용한다"의 정책을 따른다.
    즉 보안상 문제가 없다고 생각되는 패킷들만 허용하고 나머지 모든 패킷들을 금지해야 한다.

(3) R-Command 서비스는 보안을 위해 사용하지 말것을 권장.
    - /etc/hosts.equiv파일삭제 또는 #ln -s /dev/null /etc/hosts.equiv)
    - .rhosts파일삭제 또는 #ln -s /dev/null .rhosts)
    - 만약 R-Command 서비스를 사용해야 할 경우 "+ +" 혹은 "+"가 포함되지 않도록 하고
      필요한 권한만 제공'							>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "."									>> $HOSTNAME/$HOSTNAME.txt 2>&1

echo '
-----US202. su명령어 사용을 제한하고 있는가?-------------------------------------
'											>> $HOSTNAME/$HOSTNAME.txt 2>&1

	if cat /etc/pam.d/su | grep "^auth" | grep "pam_wheel.so use_uid" > /dev/null
	then
	  echo "(1) su 명령어을 wheel그룹으로 사용 제한 : OK"			>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo "(1) su 명령어을 wheel그룹으로 사용 제한 : NO"			>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  ## /etc/pam.d/su 파일의 wheel 설정 스크립트 생성
	  echo '
	  # /etc/pam.d/su 파일에 auth requried pam_wheel.so use_uid 옵션 추가
	  sed -i "/pam_wheel.so use_uid/s/#auth/auth/g" /etc/pam.d/su'		>> $HOSTNAME/PatchScript.sh 2>&1
	fi

echo '
(2) 일반 사용자의 su 명령의 사용권한 제한
- /usr/bin/su 파일 권한'						>> $HOSTNAME/$HOSTNAME.txt 2>&1
	ls -l /usr/bin/su						>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo '
- /bin/su 파일 권한'							>> $HOSTNAME/$HOSTNAME.txt 2>&1
	ls -l /bin/su							>> $HOSTNAME/$HOSTNAME.txt 2>&1
## 해당 su 파일의 설정 권한 변경 스크립트
	echo "chmod 4750 /usr/bin/su"				>> $HOSTNAME/PatchScript.sh 2>&1
	echo "chmod 4750 /bin/su"					>> $HOSTNAME/PatchScript.sh 2>&1
echo '
@ 권고사항
(1) su명령어 사용을 wheel 사용자 그룹에 속한 계정만 가능하도록 제한할 수 있도록
    /etc/pam.d/su 설정파일에 설정 "auth required pam_wheel.so use_uid"을 추가하도록 한다.

(2) 권한있는 사용자만 su 명령어를 사용하도록 파일 권한 변경(그룹으로 관리)
    권한은 4750(-rwsr-x---) 권고, 455(-r-sr-xr-x)은 취약함
.'									>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo " "								>> $HOSTNAME/$HOSTNAME.txt 2>&1

####################################################################################################################################
####################################################################################################################################
echo '
***************************** 3. 시스템 보안 ********************************************
*****************************************************************************************

-----US301. 사용자 기본 환경 파일의 권한이 적절한가?-------------------------------------
'									>> $HOSTNAME/$HOSTNAME.txt 2>&1
	if (( 644 >= `stat -c "%a" /etc/profile` ))
	then
	  echo "/etc/profile 권한설정: OK"				>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  ls -al /etc/profile					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo "/etc/profile 권한설정: 변경필요(스크립트 참조)"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  echo "# /etc/profile 퍼미션 변경"			>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "chmod 640 /etc/profile"				>> $HOSTNAME/PatchScript.sh 2>&1
	fi

	for File in `find / -name .profile -ls | awk '{print $11}'`
	do
	  if (( 640 >= `stat -c "%a" $File` ))
	  then
	    echo "$File 권한설정: OK"				>> $HOSTNAME/$HOSTNAME.txt 2>&1
	    ls -al $File						>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  else
	    echo "$File 권한설정: 변경필요(스크립트 참조)"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	    echo "# $File 퍼미션 변경"				>> $HOSTNAME/PatchScript.sh 2>&1
	    echo "chmod 640 $File"					>> $HOSTNAME/PatchScript.sh 2>&1
	  fi
	done

	for File in `find / -name .login -ls | awk '{print $11}'`
	do
	  if (( 640 >= `stat -c "%a" $File` ))
	  then
	    echo "$File 권한설정: OK"				>> $HOSTNAME/$HOSTNAME.txt 2>&1
	    ls -al $File						>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  else
	    echo "$File 권한설정: 변경필요(스크립트 참조)"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	    echo "# $File 퍼미션 변경"				>> $HOSTNAME/PatchScript.sh 2>&1
	    echo "chmod 640 $File"					>> $HOSTNAME/PatchScript.sh 2>&1
	  fi
	done

	for File in `find / -name .cshrc -ls | awk '{print $11}'`
	do
	  if (( 640 >= `stat -c "%a" $File` ))
	  then
	    echo "$File 권한설정: OK"				>> $HOSTNAME/$HOSTNAME.txt 2>&1
	    ls -al $File						>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  else
	    echo "$File 권한설정: 변경필요(스크립트 참조)"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	    echo "# $File 퍼미션 변경"				>> $HOSTNAME/PatchScript.sh 2>&1
	    echo "chmod 640 $File"					>> $HOSTNAME/PatchScript.sh 2>&1
	  fi
	done

	for File in `find / -name .bashrc -ls | awk '{print $11}'`
	do
	  if (( 640 >= `stat -c "%a" $File` ))
	  then
	    echo "$File 권한설정: OK"				>> $HOSTNAME/$HOSTNAME.txt 2>&1
	    ls -al $File						>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  else
	    echo "$File 권한설정: 변경필요(스크립트 참조)"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	    echo "#$File 퍼미션 변경"				>> $HOSTNAME/PatchScript.sh 2>&1
	    echo "chmod 640 $File"					>> $HOSTNAME/PatchScript.sh 2>&1
	  fi
	done

	for File in `find / -name .bash_profile -ls | awk '{print $11}'`
	do
	  if (( 640 >= `stat -c "%a" $File` ))
	  then
	    echo "$File 권한설정: OK"				>> $HOSTNAME/$HOSTNAME.txt 2>&1
	    ls -al $File						>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  else
	    echo "$File 권한설정: 변경필요(스크립트 참조)"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	    echo "# $File 퍼미션 변경"				>> $HOSTNAME/PatchScript.sh 2>&1
	    echo "chmod 640 $File"					>> $HOSTNAME/PatchScript.sh 2>&1
	  fi
	done

	for File in `find / -name .bash_history -ls | awk '{print $11}'`
	do
	  if (( 640 >= `stat -c "%a" $File` ))
	  then
	    echo "$File 권한설정: OK"				>> $HOSTNAME/$HOSTNAME.txt 2>&1
	    ls -al $File						>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  else
	    echo "$File 권한설정: 변경필요(스크립트 참조)"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	    echo "#$File 퍼미션 변경"				>> $HOSTNAME/PatchScript.sh 2>&1
	    echo "chmod 640 $File"					>> $HOSTNAME/PatchScript.sh 2>&1
	  fi
	done

	for File in `find / -name .mysql_history -ls | awk '{print $11}'`
	do
	  if (( 640 >= `stat -c "%a" $File` ))
	  then
	    echo "$File 권한설정: OK"				>> $HOSTNAME/$HOSTNAME.txt 2>&1
	    ls -al $File						>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  else
	    echo "$File 권한설정: 변경필요(스크립트 참조)"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	    echo "#환경설정 파일 $File 퍼미션 변경"		>> $HOSTNAME/PatchScript.sh 2>&1
	    echo "chmod 640 $File"					>> $HOSTNAME/PatchScript.sh 2>&1
	  fi
	done

echo '
@권고사항
- 환경 설정 파일의 접근권한을 640으로 설정할 것을 권고.'	>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "."								>> $HOSTNAME/$HOSTNAME.txt 2>&1

echo '
-----US302. 주요 디렉토리 및 중요한 파일의 권한 설정이 적절한가?-------------------------

(1) /etc, /sbin, /usr 권한 설정
'				 					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	ls -dl /etc /sbin /usr					>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo '
(2) 중요 파일 권한 설정
'			 						>> $HOSTNAME/$HOSTNAME.txt 2>&1

					# 중요 파일권한이 권고사항보다 낮을 경우 자동 설정 스크립트 생성.
	Value=600			# 권장 퍼미션값
	File=/etc/hosts.allow	# 중요 파일
	PN=`stat -c "%a" $File`	# 점검파일의 퍼미션값
	if (( "$PN" <= "$Value" ))
	then
	  echo "$File의 퍼미션 : OK"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo "# $File 파일 퍼미션 조정 : $Value"			>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "chmod $Value $File"						>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "$File의 퍼미션 조정 필요(스크립트참조) : $Value"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	fi

echo " "									>> $HOSTNAME/$HOSTNAME.txt 2>&1
	Value=644
	File=/etc/motd
	PN=`stat -c "%a" $File`
	if (( "$PN" <= "$Value" ))
	then
	  echo "$File의 퍼미션 : OK"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo "# $File 파일 퍼미션 조정 : $Value"			>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "chmod $Value $File"						>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "$File의 퍼미션 조정 필요(스크립트참조) : $Value"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	fi
echo " "									>> $HOSTNAME/$HOSTNAME.txt 2>&1
	Value=771
	File=/etc
	PN=`stat -c "%a" $File`
	if (( "$PN" <= "$Value" ))
	then
	  echo "$File의 퍼미션 : OK"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo "# $File 파일 퍼미션 조정 : $Value"			>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "chmod $Value $File"						>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "$File의 퍼미션 조정 필요(스크립트참조) : $Value"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	fi
echo " "									>> $HOSTNAME/$HOSTNAME.txt 2>&1
	Value=771			# 권장 퍼미션값
	File=/bin			# 중요 파일
	PN=`stat -c "%a" $File`	# 점검파일의 퍼미션값
	if (( "$PN" <= "$Value" ))
	then
	  echo "$File의 퍼미션 : OK"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo "# $File 파일 퍼미션 조정 : $Value"			>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "chmod $Value $File"						>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "$File의 퍼미션 조정 필요(스크립트참조) : $Value"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	fi
echo " "									>> $HOSTNAME/$HOSTNAME.txt 2>&1
	Value=771
	File=/usr/bin
	PN=`stat -c "%a" $File`
	if (( "$PN" <= "$Value" ))
	then
	  echo "$File의 퍼미션 : OK"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo "# $File 파일 퍼미션 조정 : $Value"			>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "chmod $Value $File"						>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "$File의 퍼미션 조정 필요(스크립트참조) : $Value"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	fi
echo " "									>> $HOSTNAME/$HOSTNAME.txt 2>&1
	Value=771
	File=/sbin
	PN=`stat -c "%a" $File`
	if (( "$PN" <= "$Value" ))
	then
	  echo "$File의 퍼미션 : OK"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo "# $File 파일 퍼미션 조정 : $Value"			>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "chmod $Value $File"						>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "$File의 퍼미션 조정 필요(스크립트참조) : $Value"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	fi
echo " "									>> $HOSTNAME/$HOSTNAME.txt 2>&1
	Value=775
	for File in /etc/init.d/*
	do
	  PN=`stat -c "%a" $File`
	  if (( "$PN" <= "$Value" ))
	  then
	    echo "$File의 퍼미션 : OK"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  else
	    echo "# $File 파일 퍼미션 조정 : $Value"			>> $HOSTNAME/PatchScript.sh 2>&1
	    echo "chmod $Value $File"					>> $HOSTNAME/PatchScript.sh 2>&1
	    echo "$File의 퍼미션 조정 필요(스크립트참조) : $Value"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  fi
	done
echo " "									>> $HOSTNAME/$HOSTNAME.txt 2>&1
	Value=755
	for File in /etc/cron.hourly/*
	do
	  PN=`stat -c "%a" $File`
	  if (( "$PN" <= "$Value" ))
	  then
	    echo "$File의 퍼미션 : OK"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  else
	    echo "# $File 파일 퍼미션 조정 : $Value"			>> $HOSTNAME/PatchScript.sh 2>&1
	    echo "chmod $Value $File"					>> $HOSTNAME/PatchScript.sh 2>&1
	    echo "$File의 퍼미션 조정 필요(스크립트참조) : $Value"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  fi
	done
echo " "									>> $HOSTNAME/$HOSTNAME.txt 2>&1
	Value=755
	for File in /etc/cron.daily/*
	do
	  PN=`stat -c "%a" $File`
	  if (( "$PN" <= "$Value" ))
	  then
	    echo "$File의 퍼미션 : OK"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  else
	    echo "# $File 파일 퍼미션 조정 : $Value"			>> $HOSTNAME/PatchScript.sh 2>&1
	    echo "chmod $Value $File"					>> $HOSTNAME/PatchScript.sh 2>&1
	    echo "$File의 퍼미션 조정 필요(스크립트참조) : $Value"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  fi
	done
echo " "									>> $HOSTNAME/$HOSTNAME.txt 2>&1
	Value=755
	for File in /etc/cron.weekly/*
	do
	  PN=`stat -c "%a" $File`
	  if (( "$PN" <= "$Value" ))
	  then
	    echo "$File의 퍼미션 : OK"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  else
	    echo "# $File 파일 퍼미션 조정 : $Value"			>> $HOSTNAME/PatchScript.sh 2>&1
	    echo "chmod $Value $File"					>> $HOSTNAME/PatchScript.sh 2>&1
	    echo "$File의 퍼미션 조정 필요(스크립트참조) : $Value"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  fi
	done
echo " "									>> $HOSTNAME/$HOSTNAME.txt 2>&1
	Value=755
	for File in /etc/cron.monthly/*
	do
	  PN=`stat -c "%a" $File`
	  if (( "$PN" <= "$Value" ))
	  then
	    echo "$File의 퍼미션 : OK"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  else
	    echo "# $File 파일 퍼미션 조정 : $Value"			>> $HOSTNAME/PatchScript.sh 2>&1
	    echo "chmod $Value $File"					>> $HOSTNAME/PatchScript.sh 2>&1
	    echo "$File의 퍼미션 조정 필요(스크립트참조) : $Value"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  fi
	done
echo " "									>> $HOSTNAME/$HOSTNAME.txt 2>&1
	Value=775
	File="$CRON_DENY"
	PN=`stat -c "%a" $File`
	if (( "$PN" <= "$Value" ))
	then
	  echo "$File의 퍼미션 : OK"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo "# $File 파일 퍼미션 조정 : $Value"			>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "chmod $Value $File"						>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "$File의 퍼미션 조정 필요(스크립트참조) : $Value"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	fi
echo " "									>> $HOSTNAME/$HOSTNAME.txt 2>&1
	Value=644
	File="$PASSWD"
	PN=`stat -c "%a" $File`
	if (( "$PN" <= "$Value" ))
	then
	  echo "$File의 퍼미션 : OK"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo "# $File 파일 퍼미션 조정 : $Value"			>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "chmod $Value $File"						>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "$File의 퍼미션 조정 필요(스크립트참조) : $Value"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	fi
echo " "									>> $HOSTNAME/$HOSTNAME.txt 2>&1
	Value=400
	File="$SHADOW"
	PN=`stat -c "%a" $File`
	if (( "$PN" <= "$Value" ))
	then
	  echo "$File의 퍼미션 : OK"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo "# $File 파일 퍼미션 조정 : $Value"			>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "chmod $Value $File"						>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "$File의 퍼미션 조정 필요(스크립트참조) : $Value"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	fi
echo " "									>> $HOSTNAME/$HOSTNAME.txt 2>&1
	Value=644
	File="$GROUP"
	PN=`stat -c "%a" $File`
	if (( "$PN" <= "$Value" ))
	then
	  echo "$File의 퍼미션 : OK"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo "# $File 파일 퍼미션 조정 : $Value"			>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "chmod $Value $File"						>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "$File의 퍼미션 조정 필요(스크립트참조) : $Value"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	fi

echo " "									>> $HOSTNAME/$HOSTNAME.txt 2>&1
	Value=644
	File="$SERVICES"
	PN=`stat -c "%a" $File`
	if (( "$PN" <= "$Value" ))
	then
	  echo "$File의 퍼미션 : OK"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo "# $File 파일 퍼미션 조정 : $Value"			>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "chmod $Value $File"						>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "$File의 퍼미션 조정 필요(스크립트참조) : $Value"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	fi

echo " "									>> $HOSTNAME/$HOSTNAME.txt 2>&1
	Value=600
	File="/var/log/messages"
	PN=`stat -c "%a" $File`
	if (( "$PN" <= "$Value" ))
	then
	  echo "$File의 퍼미션 : OK"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo "# $File 파일 퍼미션 조정 : $Value"			>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "chmod $Value $File"						>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "$File의 퍼미션 조정 필요(스크립트참조) : $Value"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	fi

echo " "									>> $HOSTNAME/$HOSTNAME.txt 2>&1
	Value=600
	File="/var/log/secure"
	PN=`stat -c "%a" $File`
	if (( "$PN" <= "$Value" ))
	then
	  echo "$File의 퍼미션 : OK"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo "# $File 파일 퍼미션 조정 : $Value"			>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "chmod $Value $File"						>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "$File의 퍼미션 조정 필요(스크립트참조) : $Value"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	fi

echo " "									>> $HOSTNAME/$HOSTNAME.txt 2>&1
	Value=600
	File="/var/log/faillog"
	PN=`stat -c "%a" $File`
	if (( "$PN" <= "$Value" ))
	then
	  echo "$File의 퍼미션 : OK"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo "# $File 파일 퍼미션 조정 : $Value"			>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "chmod $Value $File"						>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "$File의 퍼미션 조정 필요(스크립트참조) : $Value"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	fi

echo " "									>> $HOSTNAME/$HOSTNAME.txt 2>&1
	Value=644
	File="/var/log/lastlog"
	PN=`stat -c "%a" $File`
	if (( "$PN" <= "$Value" ))
	then
	  echo "$File의 퍼미션 : OK"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo "# $File 파일 퍼미션 조정 : $Value"			>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "chmod $Value $File"						>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "$File의 퍼미션 조정 필요(스크립트참조) : $Value"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	fi

echo '
(3) 로그 파일 권한 설정 ' 													>> $HOSTNAME/$HOSTNAME.txt 2>&1
	ls -alL /var/log | egrep 'secrue|wtmp|utmp|btmp|syslog|sulog|pacct|authlog|messages|loginlog|lastlog'	>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo '
@권고사항
(1) 주요 디렉토리의 접근 권한을 755로 설정함
(2) 시스템 로그파일의 권한 확인 644이하
(3) 일반 사용자의 명령어 패스는
    /usr/local/bin:usr/local/mysql/bin:/home/hosting/bin/
    일반사용자가 사용가능한 명령어를 모두 이것에 둠.'			>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "."									>> $HOSTNAME/$HOSTNAME.txt 2>&1

## 주요 관리자요 명령어 권한 설정
echo '#주요 관리자용 명령어 퍼미션 조정
chmod 100 /usr/bin/top
chmod 100 /usr/bin/pstree
chmod 100 /usr/bin/w
chmod 100 /bin/ps
chmod 100 /usr/bin/who
chmod 100 /usr/bin/find
chmod 100 /bin/df
chmod 100 /bin/netstat
chmod 100 /sbin/ifconfig
chmod 100 /usr/sbin/lsof
chmod 100 /usr/bin/make
chmod 100 /usr/bin/gcc
chmod 100 /usr/bin/g++
chmod 100 /usr/bin/c++

# 중요한 파일 퍼미션과 소유권 제한 및 점검
chmod 644 /etc/service
chmod 600 /etc/xinetd
chmod 644 /etc/mail/aliases
chmod 600 /etc/httpd/conf/httpd.conf
chmod 644 /var/log/wtmp
chmod 644 /var/run/utmp
chmod 644 /etc/motd
chmod 644 /etc/mtab
chmod 600 /etc/syslog.conf
'									>> $HOSTNAME/PatchScript.sh 2>&1

echo '
-----US303. /etc/hosts 파일의 내용 및 권한 설정이 적절한가?------------------------------

(1) /etc/hosts 파일 권한 설정'					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	PN=`stat -c "%a" $HOSTS`	# 퍼미션값
	if (( "$PN" <= 644 ));	# 퍼미션값 미만확인
	then
	  echo "$HOSTS 권한설정: OK"				>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  ls -ald $HOSTS						>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo "$HOSTS 권한설정: 변경필요(스크립트 참조)"	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  echo "chmod 644 $HOSTS"					>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "$HOSTS 파일 퍼미션 조정 : 644"			>> $HOSTNAME/PatchScript.sh 2>&1
	fi
echo '
(2) /etc/hosts 파일 내용 확인' 					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	cat $HOSTS							>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo '
@권고사항
- /etc/hosts 설정 권한이 644이하, 소유주가 root인지 점검
- /etc/hosts 파일에 불필요한 내용이 있는지 점검'			>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "."								>> $HOSTNAME/$HOSTNAME.txt 2>&1

echo '
-----US304. TMP 디렉토리의 권한을 Sticky bit로 설정 하였는가?----------------------------
'									>> $HOSTNAME/$HOSTNAME.txt 2>&1
	ls -ld /tmp /var/tmp						>> $HOSTNAME/$HOSTNAME.txt 2>&1
	echo "
	# /tmp와 /var/tmp에 대한 디렉토리 권한 설정 자동 스크립트 생성
	chmod 1777 /tmp
	chmod 1777 /var/tmp"						>> $HOSTNAME/PatchScript.sh 2>&1
echo '
@ 권고사항
- /tmp, /var/tmp디렉토리의 권한이 1777(drwxrwxrwt)임을 확인'	>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "."								>> $HOSTNAME/$HOSTNAME.txt 2>&1

echo '
-----US304. PATH 설정이 적절한가?--------------------------------------------------------

(1) Bash의 경우, 환경설정파일 권한 및 PATH설정'			>> $HOSTNAME/$HOSTNAME.txt 2>&1
	for LIST in `find / -name .bash_profile -exec ls {} \;`
	do
	  echo "- $LIST 파일 상태"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  stat $LIST | grep 'Uid:'					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  cat $LIST | grep -i path					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	done
echo '
(2) C Shell의 경우, 환경설정파일 권한 및 PATH설정'		>> $HOSTNAME/$HOSTNAME.txt 2>&1
	for LIST in `find / -name .cshrc -exec ls {} \;`
	do
	  echo "$LIST 파일 상태"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  stat $LIST | grep 'Uid:'					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  cat $LIST | grep -i path					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	done
echo " "								>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo '
@권고사항
root계정의 PATH환경변수에 '.'이 포함되어 있는지 확인(제거)'	>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "."								>> $HOSTNAME/$HOSTNAME.txt 2>&1

echo "
-----US305. UMASK 설정이 적절한가?-------------------------------------------------------

(1) /etc/pam.d/login 점검"						>> $HOSTNAME/$HOSTNAME.txt 2>&1
	cat /etc/pam.d/login | grep -i umask			>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "
(2) umask 명령확인"							>> $HOSTNAME/$HOSTNAME.txt 2>&1
	umask								>> $HOSTNAME/$HOSTNAME.txt 2>&1
	echo "# root의 umask값을 077으로 수정"			>> $HOSTNAME/PatchScript.sh 2>&1
	echo "umask 077"						>> $HOSTNAME/PatchScript.sh 2>&1
echo '
@권고사항
- UMASK 값이 022 혹은 027인지 점검함
- 특히 root의 umask 값은 077로 정해서 읽기, 쓰기, 실행을 루트가
  직접 chmod를 써서 바꿔 주지 않는 한 다른 사용자가 못하도록
  만드는 것이 좋다(스크립트 참조)'					>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "."								>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo " "								>> $HOSTNAME/$HOSTNAME.txt 2>&1

echo "
-----US306. SUID/SGID의 설정이 적절한가?-------------------------------------------------
"									>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "* SetUID SetGID 체크하기 "								>> $HOSTNAME/$HOSTNAME.txt 2>&1
	find / -type f \( -perm -004000 -o -perm -002000 \) -exec ls -lg {} \;	>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo '
@권고사항
- 아래 파일에 대하여 SUID/SGID제거, 패치 스크립트 참조
- /usr/bin/chage, /usr/bin/gpasswd, /usr/bin/wall, /usr/bin/chfn, /usr/bin/newgrp
- /usr/bin/write, /usr/bin/at, /usr/sbin/usrnetctl, /usr/sbin/userhelper, /bin/mount
- /bin/umount, /usr/sbin/lockdev, /bin/ping, /usr/sbin/traceroute'			>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "."											>> $HOSTNAME/$HOSTNAME.txt 2>&1
## 권고사항에 따라 SUID/SGID 제거 자동 스크립트 생성
echo '
# 권고사항에 따라 SUID/SGID 제거
chmod -s /usr/bin/chage /usr/bin/gpasswd /usr/bin/wall /usr/bin/chfn \
/usr/bin/newgrp /usr/bin/write /usr/bin/at /usr/sbin/usrnetctl /usr/sbin/userhelper \
/bin/mount /bin/umount /usr/sbin/lockdev /bin/ping /usr/sbin/traceroute'		>> $HOSTNAME/PatchScript.sh 2>&1
echo " " 											>> $HOSTNAME/PatchScript.sh 2>&1

echo "
-----US307. 백도어 점검-----------------------------------------------------------------

(1) find를 이용한 백도어 점검(/Dev 폴더의 정상상태 확인)"		>> $HOSTNAME/$HOSTNAME.txt 2>&1
	find /dev -type f -exec ls -l {} \;				>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "
(2) chkrootkit 툴을 이용한 백도어 점검
"										>> $HOSTNAME/$HOSTNAME.txt 2>&1
	~/chkrootkit*/chkrootkit						>> $HOSTNAME/$HOSTNAME.txt 2>&1

echo '
@권고사항
- /dev 폴더에 장치명과 다른 파일이 있을 경우 백도어일 가능성이 높음.
- "chkrootkit" 백도어 점검툴을 이용하여 다시 한번 확인 필요'		>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "." 									>> $HOSTNAME/$HOSTNAME.txt 2>&1

echo "
-----US308. 소유자없는 파일 및 디렉토리 찾기---------------------------------------------
"										>> $HOSTNAME/$HOSTNAME.txt 2>&1
	find / -nouser -o -nogroup -print					>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "
@권고사항
- 주인이 없는 무소속의 파일들 또한 침입자가 시스템에 들어왔다는 징후일 수 있다."	>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "."											>> $HOSTNAME/$HOSTNAME.txt 2>&1

echo "
-----US310. forward파일 체크------------------------------------------------------------
"										>> $HOSTNAME/$HOSTNAME.txt 2>&1
	find / -name '.forward' -exec cat {} \; -print			>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo '
@권고사항
- .forward파일 생성시 중요한 사항으로 보안성 강화를 위하여 .forward파일의 퍼미션과 .froward파일을
  포함하는 디렉토리(사용자 계정 디렉토리)에 group의 퍼미션에 쓰기 권한이 없어야 sendmail 데몬이
  .forward파일을 읽어서 포워딩 기능을 정상적으로 진행한다.
- CentOS 의 기본적인 유저생성시 생성되는 디렉토리 퍼미션은 700 이지만, 기본 파일 생성 퍼미션이
  664로 생성되어 그룹 퍼미션에 쓰기 권한이 있기 때문에 .forward파일만 생성하였다고 해서 포워딩이
  정상적으로 진행되지 않는다. 이럴때는 644로 .froward 파일의 퍼미션을 변경해 준다.'	>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "."											>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo " " 											>> $HOSTNAME/$HOSTNAME.txt 2>&1

###################################################################################################################################
###################################################################################################################################
echo "
***************************** 4. 서비스 보안 ********************************************
*****************************************************************************************
"										 		>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "
-----US401. 불필요한 서비스를 중지하였는가?----------------------------------------------

* 보안상 위험하거나 불필요한 서비스 실행목록"						>> $HOSTNAME/$HOSTNAME.txt 2>&1
	service --status-all | egrep "apmd|cups|xntpd|portmap|sound|netfs|rstatd|rusersd|rwalld|bootparamd|squid|yppasswdd|ypserv|dhcpd|atd|pcmcia|snmpd|routed|lpd|mars-nwe|nfs|amd|ypbind|xfs|innd|linuxconf"|grep pid  >> $HOSTNAME/$HOSTNAME.txt 2>&1
echo '
@권고사항
- S05apmd : laptop에서 전원관리를 위해 필요하므로 서버에서는 필요없다.(적용)
- S10cups : Common Unix Printing System으로 서버에서는 필요없다.(적용)
- S10xntpd : Network time protocal이다. 현재 우리서버는 ntp를 사용중이다.(보존)
- S11portmap : NIX나 NFS서비스 이용시 R로 시작되는 서비스에 대한 port를 mapping시켜주는 서비스이므로 보안상 문제가 많다.(적용)
- S15sound : 서버에서 사운드를 서비스 하지 않으므로 필요없다.
- S15netfs : nfs client가 nfs server를 마운트 할 때 필요하므로 역시 필요없으나, 사무실 서버에서는 사용중(옵션)
- S20rstatd, S20rwhod, S20rwalld : R로 시작하는 서비스는 인증과정이 취약하고 Remote에서 실행하는 것이므로 반드시 서비스를 하지 않도록 해야 한다(적용)
- S20bootparamd : 하드나 플로피 등 부팅 수단이 없을 때 이용하는 것으로 반드시 서비스하지 않아야 한다.(적용)
- S25squid : squid 프록시 서버를 가동하는 설정으로써 우리 서비스에서는 사용하지 않으므로 사용하지 않는다.(적용)
- S34yppasswdd : NIS서버에서 필요하므로 필요없다.(적용)
- S35ypserv : 역시 NIS서버에서 필요한 설정이므로 필요없다.(적용)
- S35dhcpd : dhcp에서 필요하므로 우리서버에서는 사용하지 않는다(적용)
- S40atd : cron과 같은 서비스로써 우리는 cron을 사용하고 있기 때문에 필요없다.(적용)
- S50snmpd : 원격의 이용자가 트래픽이나 시스템에 대한 정보를 필요로할 때 사용되는 프로세스로 snmp community string을 엄격하게 설정하여 사용해야 한다.(옵션)
- S55named : DNS서비스를 제공한다면 이용하지만 그렇지 않으면 삭제한다.(옵션)
- SSrouted : 라우터가 아닌 이상 일반 서버에서는 삭제한다.(적용)
- S60lpd : 프린터 서버가 아닌 이상 반드시 삭제한다.(적용)
- S60mars-nwe : Netware에서 쓰는 파일이나 Printer server이므로 삭제한다.(적용)
- S60nfs : NFS서버에서 필요하므로 nfs를 서비스하지 않는다면 삭제한다.(적용)
- S72amd : AutoMount daemon으로 원격지의 파일 시스템을 마운트할때 필요하다. amd는 전통적으로 보안 취약성이 있으므로 삭제한다
- S80sendmail : sendmail 데몬으로 메일서비스를 제공하지 않는다면 삭제한다.(옵션)
- S87ypbind : NIS를 쓸 때 필요하다. 사용하지 않는다면 반드시 삭제(적용)
- S90xfs : X front server로, 서버에서는 X-Windows서비스를 하지 않는다면 삭제.(적용)
- S95innd : News server로 News서비스를 하지 않는다면 반드시 삭제(적용)
- S99linuxconf : 원격지에서 브라우저를 통해 리눅스 시스템의 설정을 변경할 수 있는 것으로 보안상 취약성을 가지고 있으므로 반드시 삭제(적용)
'				>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "."			>> $HOSTNAME/$HOSTNAME.txt 2>&1

echo "# 불필요한 서비스 3레벨 off 설정"					>> $HOSTNAME/PatchScript.sh 2>&1
	for SVC in `chkconfig --list | egrep "apmd|cups|xntpd|portmap|sound|netfs|rstatd|rusersd|rwalld|bootparamd|squid|yppasswdd|ypserv|dhcpd|atd|pcmcia|snmpd|routed|lpd|mars-nwe|nfs|amd|ypbind|xfs|innd|linuxconf" | grep 3:활성 | awk '{print $1}'`
	do
	  echo "chkconfig --level 3 `echo "$SVC"` off"			>> $HOSTNAME/PatchScript.sh 2>&1
	done

echo "
-----US403. 익명 FTP를 사용하지 않는가?--------------------------------------------------

* FTP 사용여부 확인" 							>> $HOSTNAME/$HOSTNAME.txt 2>&1
	if ps -ef | grep ftp | grep -v 'grep' > /dev/nul
	then
	  echo "FTP 서버 운영 상태 : On"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  echo "* $PASSWD에 ftp 계정 확인 "				>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  cat $PASSWD | grep -i ftp						>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo "FTP 서버 운영 상태 : Off"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	fi
echo "
@권고사항
- Anonymous FTP 제한을 위해 ftp 계정 삭제확인"				>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "."									>> $HOSTNAME/$HOSTNAME.txt 2>&1


echo "
-----US404. 서비스 배너에 시스템 정보를 제공하지 않는가?---------------------------------

* Telnet 배너 점검"									>> $HOSTNAME/$HOSTNAME.txt 2>&1
	ls -l /etc/issue								>> $HOSTNAME/$HOSTNAME.txt 2>&1
	cat $BANNER | grep -i banner | grep -v '#'				>> $HOSTNAME/$HOSTNAME.txt 2>&1

echo "
@권고사항
'Authorized users only. All activity may be monitored and reported'와 같은 경고문 띄움
sendmail은 'SmtpGreetingMessage'의 모든 메시지 삭제함"				>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "."										>> $HOSTNAME/$HOSTNAME.txt 2>&1

###################################################################################################################################
###################################################################################################################################
echo "
******************************* 5. 모니터링 *********************************************
*****************************************************************************************

-----US501. syslog가 실행되고 있는가?----------------------------------------------------
"											>> $HOSTNAME/$HOSTNAME.txt 2>&1

	ps -ef |grep syslog | grep -v "grep"					>> $HOSTNAME/$HOSTNAME.txt 2>&1

echo "
-----US502. 로그기록 설정이 적절한가?----------------------------------------------------
"											>> $HOSTNAME/$HOSTNAME.txt 2>&1
	cat $SYSLOG_CONF | grep -v '^#'						>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo '
@권고사항
/etc/syslog.conf 다음의 설정을 권고함
-----------------------------------------------------------
*.info;mail.none;authpriv.none;cron.none	/var/log/messages
authpriv.*		/var/log/secure
mail.*		-/var/log/maillog
cron.*		/var/log/cron
local7.*		/var/log/boot.log
*.alert		root
*.emerg		*
-----------------------------------------------------------'			>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "." 										>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo " " 										>> $HOSTNAME/$HOSTNAME.txt 2>&1

echo "
-----US503. SU 로그를 기록하고 있는가?---------------------------------------------------

(1) /etc/syslog.conf 점검" 								>> $HOSTNAME/$HOSTNAME.txt 2>&1
	cat /etc/syslog.conf | grep -i auth					>> $HOSTNAME/$HOSTNAME.txt 2>&1

echo "
(2) su명령어의 사용내역을 확인(로그메세지).
........................................................................................."	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	cat /var/log/messages | grep root 								>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo '.........................................................................................
@권고사항
- sulog를 기록하도록 설정하였는지 여부와 실제 sulog 존재 여부를 확인'		>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "."										>> $HOSTNAME/$HOSTNAME.txt 2>&1

echo "
***************************** 6. 기타 보안관리 ******************************************
*****************************************************************************************

-----US601. 스케줄링(scheduling)의 작업내용 및 사용권한이 적절한가?----------------------

* 주기적으로 수행되는 스케줄 내역 조회(cron)"						>> $HOSTNAME/$HOSTNAME.txt 2>&1
	for HD in `cat $PASSWD | awk -F: '{print $1}' | sort | uniq`
	do
	  echo $HD										>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  crontab -u $HD -l 									>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  echo ".................................................................."	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	done
echo "
* 일회성으로 수행되는 스케줄 내역 조회(at)"	 					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	for HD in `cat $PASSWD | awk -F: '{print $1}' | sort | uniq`
	do
	  echo $HD										>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  atq $HD										>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  echo ".................................................................."	>> $HOSTNAME/$HOSTNAME.txt 2>&1
	done
echo "."											>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo " " 											>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "* cron.allow 점검"									>> $HOSTNAME/$HOSTNAME.txt 2>&1
	cat $CRON_ALLOW									>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo " " 											>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "* cron.deny 점검"									>> $HOSTNAME/$HOSTNAME.txt 2>&1
	cat $CRON_DENY									>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo " " 											>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "
@권고사항
- *.allow파일에는 이용할 사용자, *.deny파일에는 제한할 사용자 추가"			>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "."											>> $HOSTNAME/$HOSTNAME.txt 2>&1

echo "
-----US602. 최신의 시스템 패치가 설치되어 있는가?----------------------------------------
"												>> $HOSTNAME/$HOSTNAME.txt 2>&1
	uname -a 										>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo " "											>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo '
@권고사항
최신 패치파일 확인
http://www.centos.org'									>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo "."											>> $HOSTNAME/$HOSTNAME.txt 2>&1


echo "
-----US603. sysctl 보안설정 점검--------------------------------------------------------
"												>> $HOSTNAME/$HOSTNAME.txt 2>&1
## sysctl 보안 적용 스크립트
#1) 브로드캐스팅 패킷관련 보안점검 및 설정
	if (( `cat /proc/sys/net/ipv4/ip_forward` && `cat /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts` ))
	then
	  echo "1) 브로드캐스팅 패킷 보안 설정 : OK"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo "1) 브로드캐스팅 패킷 보안 설정 : NO"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  echo '#1. 브로드캐스팅 패킷 공격에 대한 커널 보안설정
	  echo "1" > /proc/sys/net/ipv4/ip_forward
	  echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts'			>> $HOSTNAME/PatchScript.sh 2>&1
	fi
#2) Deny Source Routing packet
	for LIST in /proc/sys/net/ipv4/conf/*/accept_source_route; do
	  if (( 0==`cat $LIST` ))
	  then
	    echo "2) $LIST 커널 보안설정: 정상(`cat $LIST`)"				>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  else
	    echo "2) $LIST 커널 보안설정: 비정상(`cat $LIST`)"				>> $HOSTNAME/$HOSTNAME.txt 2>&1
	    echo "#2. Deny Source Routing packet 설정"					>> $HOSTNAME/PatchScript.sh 2>&1
	    echo "echo "0" > $LIST"								>> $HOSTNAME/PatchScript.sh 2>&1
	  fi
	done
#3) Configuration tcp syncookies
	if (( 1==`cat /proc/sys/net/ipv4/tcp_syncookies` ))
	then
	  echo "3) tcp syncookies 보안설정 : OK"						>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo "3) tcp syncookies 보안설정 : NO"						>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  echo "#3. tcp syncookies 공격에 대한 커널 보안설정"				>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "echo "1" > /proc/sys/net/ipv4/tcp_syncookies"				>> $HOSTNAME/PatchScript.sh 2>&1
	fi
#4) Deny ICMP redirect
	for LIST in /proc/sys/net/ipv4/conf/*/accept_redirects; do
	if (( 0==`cat $LIST` ))
	then
	  echo "4) ICMP redirect 공격에 대한 보안설정 : OK"				>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo "4) ICMP redirect 공격에 대한 보안설정 : NO"				>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  echo "#4. IPCMP redirect 거부공격에 대한 커널 보안설정"			>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "echo "0" > $LIST"								>> $HOSTNAME/PatchScript.sh 2>&1
	fi
	done
#5) Prevent Spoofing
	for LIST in /proc/sys/net/ipv4/conf/*/rp_filter; do
	if (( 1==`cat $LIST` ))
	then
	  echo "5) Spoofing공격에 대한 보안설정 : OK"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo "5) Spoofing공격에 대한 보안설정 : NO"					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  echo "#5. Spoofing공격에 대한 커널 보안설정"					>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "echo "1" > $LIST"								>> $HOSTNAME/PatchScript.sh 2>&1
	fi
	done
#6) Log for abnomally packet
	for LIST in /proc/sys/net/ipv4/conf/*/log_martians; do
	if (( 1==`cat $LIST` ))
	then
	  echo "6) 비정상 패킷에 대한 로그설정 : OK "					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo "6) 비정상 패킷에 대한 로그설정 : NO "					>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  echo "#6. 비정상 패킷에 대한 로그 커널설정 실시"				>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "echo "1" > $LIST"								>> $HOSTNAME/PatchScript.sh 2>&1
	fi
	done
#7) source validation by reversed path (RFC1812).
	if (( 1==`cat /proc/sys/net/ipv4/conf/all/rp_filter` ))
	then
	  echo "7) source validation by reversed path (RFC1812) 설정: OK"			>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo "7) source validation by reversed path (RFC1812) 설정: NO"			>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  echo "#7. source validation by reversed path (RFC1812) 커널설정"			>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "echo "1" > /proc/sys/net/ipv4/conf/all/rp_filter"				>> $HOSTNAME/PatchScript.sh 2>&1
	fi
# II.Configuration for Firewall
	if (( 30==`cat /proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_syn_recv` ))
	then
	  echo "8) source validation by reversed path (RFC1812) 설정: OK"			>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo "8) source validation by reversed path (RFC1812) 설정: NO"			>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  echo "#8. source validation by reversed path (RFC1812) 커널설정"			>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "echo "30" > /proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_syn_recv"	>> $HOSTNAME/PatchScript.sh 2>&1
	fi

	if (( 30==`cat /proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_time_wait` ))
	then
	  echo "9) source validation by reversed path (RFC1812) 설정: OK"			>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo "9) source validation by reversed path (RFC1812) 설정: NO"			>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  echo "#9. source validation by reversed path (RFC1812) 커널설정"			>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "echo "30" > /proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_time_wait">> $HOSTNAME/PatchScript.sh 2>&1
	fi

	if (( 30==`cat /proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_fin_wait` ))
	then
	  echo "10) source validation by reversed path (RFC1812) 설정: OK"			>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo "10) source validation by reversed path (RFC1812) 설정: NO"			>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  echo "source validation by reversed path (RFC1812) 커널설정"				>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "echo "30" > /proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_fin_wait"	>> $HOSTNAME/PatchScript.sh 2>&1
	fi

	if (( 28800==`cat /proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_established` ))
	then
	  echo "11) source validation by reversed path (RFC1812) 설정: OK"			>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo "11) source validation by reversed path (RFC1812) 설정: NO"			>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  echo "#11. source validation by reversed path (RFC1812) 커널설정"			>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "echo "28800" > /proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_established"	>> $HOSTNAME/PatchScript.sh 2>&1
	fi

	if (( 327680==`cat /proc/sys/net/ipv4/netfilter/ip_conntrack_max` ))
	then
	  echo "12) source validation by reversed path (RFC1812) 설정: OK"			>> $HOSTNAME/$HOSTNAME.txt 2>&1
	else
	  echo "12) source validation by reversed path (RFC1812) 설정: NO"			>> $HOSTNAME/$HOSTNAME.txt 2>&1
	  echo "#12. source validation by reversed path (RFC1812) 커널설정"			>> $HOSTNAME/PatchScript.sh 2>&1
	  echo "echo "327680" > /proc/sys/net/ipv4/netfilter/ip_conntrack_max"		>> $HOSTNAME/PatchScript.sh 2>&1
	fi

echo " "
echo "* System Information Query End "
echo " "
echo "* System Information Query End " 									>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo " "													>> $HOSTNAME/$HOSTNAME.txt 2>&1

echo "* End Time "
	date
echo " "

echo "* End Time " 												>> $HOSTNAME/$HOSTNAME.txt 2>&1
	date 													>> $HOSTNAME/$HOSTNAME.txt 2>&1
echo " "													>> $HOSTNAME/$HOSTNAME.txt 2>&1



main(){
HOSTNAME=`hostname`
[[ -d ${HOSTNAME} ]] || mkdir ${HOSTNAME}
chmod 600 ${HOSTNAME}/CheckResultList.txt
chmod 700 ${HOSTNAME}/PatchScript.sh
cd ${HOSTNAME}
exec 99<>CheckResultList.txt
exec 98<>PatchScript.sh

case "${1}" in
"CheckList")
echo $BOLD'
***************************************************************************
*                                                                         *
*                  SAMW SEcure CheckList (by cookyman)                    *
*                                                                         *
*       Copyright 2012 Snapthinking Co. Ltd. All right Reserved           *
*                                                                         *
***************************************************************************
'>>&99
;;

"PatchScript")
echo $BOLD'
***************************************************************************
*                                                                         *
*          Patch Script for the Checklist Result (by cookyman)            *
*                                                                         *
*       Copyright 2012 Snapthinking Co. Ltd. All right Reserved           *
*                                                                         *
***************************************************************************
'>>&98
;;
"*")
exit ${ERROR99}
;;

exec 99<&-
exec 98<&-
}

exit 0
