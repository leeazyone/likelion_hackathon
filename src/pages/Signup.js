import React, { useState, useRef, useEffect } from 'react' // React, 훅 불러오기
import { Link, useNavigate } from 'react-router-dom' // 라우팅 관련 훅 불러오기
import '../css/Signup.css' // 스타일시트

// (공통) 도메인과 기능에 api가 붙는 이유: cannot GET 오류를 해결하기 위해 백엔드 처리를 함, 안 붙어있으면 백엔드(nginx, express 등)에서 받지 않고 React에서 index.html로 처리 -> 기능과 페이지 이동을 구분하기 위해 사용

const Signup = () => {
  // 회원가입 입력값 상태 관리
  const [formData, setFormData] = useState({
    회원id: '',
    이름: '',
    이메일: '',
    비밀번호: '',
    비밀번호확인: '',
  })

  const navigate = useNavigate() // 페이지 이동 함수

  // 입력값 변경 핸들러
  const handleChange = (e) => {
    const { name, value } = e.target
    setFormData({ ...formData, [name]: value }) // 해당 필드만 값 변경
  }

  // 이메일 인증 관련 상태
  const [emailVerified, setEmailVerified] = useState(false) // 인증 성공 여부
  const [verifyCode, setVerifyCode] = useState('') // 입력한 인증코드
  const [codeSent, setCodeSent] = useState(false) // 인증코드 발송 여부
  const [timer, setTimer] = useState(0) // 타이머(초)
  const [timerActive, setTimerActive] = useState(false) // 타이머 동작 여부
  const timerRef = useRef(null) // 타이머 ref

  // 인증코드 발송 함수
  const handleSendCode = async () => {
    if (!formData.이메일) {
      alert('이메일을 입력하세요.')
      return
    }
    try {
      // 인증코드 발송 API 요청
      const response = await fetch(
        'https://joongbu.store/api/send-verification',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include', // 쿠키 포함
          body: JSON.stringify({ email: formData.이메일 }),
        }
      )
      const data = await response.json()
      if (response.ok) {
        alert('인증코드가 발송되었습니다.')
        setCodeSent(true) // 발송 성공 시 버튼/타이머 상태 변경
        setTimer(180) // 3분(180초) 타이머 시작
        setTimerActive(true)
      } else {
        alert(data.error || '인증코드 발송 실패')
      }
    } catch (err) {
      alert('서버 오류')
    }
  }

  // 타이머 관리 (1초마다 감소)
  useEffect(() => {
    if (timerActive && timer > 0) {
      timerRef.current = setTimeout(() => setTimer(timer - 1), 1000)
    } else if (timer === 0) {
      setTimerActive(false)
      clearTimeout(timerRef.current)
    }
    return () => clearTimeout(timerRef.current)
  }, [timer, timerActive])

  // 인증코드 확인 함수
  const handleVerifyCode = async () => {
    if (!formData.이메일 || !verifyCode) {
      alert('이메일과 인증코드를 입력하세요.')
      return
    }
    try {
      // 인증코드 확인 API 요청
      const response = await fetch('https://joongbu.store/api/verify-code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email: formData.이메일, code: verifyCode }),
      })
      const data = await response.json()
      if (response.ok) {
        alert('이메일 인증이 완료되었습니다.')
        setEmailVerified(true) // 인증 성공 시 상태 변경
        setTimerActive(false) // 타이머 종료
        setTimer(0)
      } else {
        alert(data.error || '인증 실패')
      }
    } catch (err) {
      alert('서버 오류')
    }
  }

  // 회원가입 제출 함수
  const handleSubmit = async (e) => {
    e.preventDefault() // 폼 기본 제출 막기

    if (!emailVerified) {
      alert('이메일 인증을 완료해주세요.')
      return
    }
    if (formData.비밀번호 !== formData.비밀번호확인) {
      alert('비밀번호가 일치하지 않습니다.')
      return
    }

    try {
      // 회원가입 API 요청
      const response = await fetch('https://joongbu.store/api/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          iduser: formData.회원id,
          userpw: formData.비밀번호,
          email: formData.이메일,
          name: formData.이름,
        }),
      })
      const data = await response.json()
      if (response.ok) {
        alert('회원가입이 완료되었습니다.')
        navigate('/login') // 회원가입 성공 시 로그인 페이지로 이동
      } else {
        alert(data.error || '회원가입 실패')
      }
    } catch (err) {
      alert('서버 오류')
    }
  }

  // 실제 렌더링 부분
  return (
    <div className="signup-wrapper">
      <div className="signup-container">
        <h1>hackathon</h1>
        <form onSubmit={handleSubmit}>
          {/* 아이디 입력 */}
          <div className="form-group">
            <label>아이디</label>
            <input
              type="text"
              name="회원id"
              value={formData.회원id}
              onChange={handleChange}
              placeholder="아이디 (10자 이내)"
              required
            />
          </div>
          {/* 이름 입력 */}
          <div className="form-group">
            <label>이름</label>
            <input
              type="text"
              name="이름"
              value={formData.이름}
              onChange={handleChange}
              placeholder="이름"
              required
            />
          </div>
          {/* 이메일 입력 및 인증코드 발송/타이머 */}
          <div className="form-group">
            <label>이메일</label>
            <input
              type="email"
              name="이메일"
              value={formData.이메일}
              onChange={handleChange}
              placeholder="이메일 주소"
              required
              disabled={emailVerified}
            />
            {/* 인증코드 발송/재발송 버튼 및 타이머 */}
            {(!codeSent || !timerActive) && !emailVerified && (
              <button
                type="button"
                className="verify-code-btn"
                onClick={handleSendCode}
                disabled={timerActive}
              >
                {codeSent && !timerActive ? '재발송' : '인증코드 발송'}
              </button>
            )}
            {codeSent && timerActive && !emailVerified && (
              <span style={{ marginLeft: '10px', color: '#555' }}>
                남은 시간: {Math.floor(timer / 60)}:
                {(timer % 60).toString().padStart(2, '0')}
              </span>
            )}
          </div>
          {/* 인증번호 입력 및 확인 */}
          <div className="form-group">
            <label>인증번호</label>
            <input
              type="text"
              name="인증번호"
              placeholder="인증번호 입력"
              value={verifyCode}
              onChange={(e) => setVerifyCode(e.target.value)}
              disabled={emailVerified}
            />
            <button
              type="button"
              className="verify-code-btn"
              onClick={handleVerifyCode}
              disabled={emailVerified || !codeSent}
            >
              인증 확인
            </button>
            {emailVerified && (
              <div style={{ color: '#1a7e1a', marginTop: 6 }}>
                이메일 인증 완료
              </div>
            )}
          </div>
          {/* 비밀번호 입력 */}
          <div className="form-group">
            <label>비밀번호</label>
            <input
              type="password"
              name="비밀번호"
              value={formData.비밀번호}
              onChange={handleChange}
              placeholder="비밀번호"
              required
            />
          </div>
          {/* 비밀번호 확인 입력 */}
          <div className="form-group">
            <label>비밀번호 확인</label>
            <input
              type="password"
              name="비밀번호확인"
              value={formData.비밀번호확인}
              onChange={handleChange}
              placeholder="비밀번호 확인"
              required
            />
          </div>
          {/* 회원가입 버튼 */}
          <div className="button-group">
            <button type="submit" className="signup-btn">
              회원가입
            </button>
          </div>
        </form>
        {/* 로그인 링크 */}
        <div className="signup-footer">
          <div>
            <span>이미 회원이라면?</span>
            <Link to="/login">로그인</Link>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Signup
