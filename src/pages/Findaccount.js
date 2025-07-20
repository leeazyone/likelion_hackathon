import React, { useState, useRef, useEffect } from 'react'
import '../css/FindAccount.css'

// (공통) 도메인과 기능에 api가 붙는 이유: cannot GET 오류를 해결하기 위해 백엔드 처리를 함, 안 붙어있으면 백엔드(nginx, express 등)에서 받지 않고 React에서 index.html로 처리 -> 기능과 페이지 이동을 구분하기 위해 사용

const FindPassword = () => {
  const [form, setForm] = useState({
    userId: '',
    email: '',
    code: '',
    newPassword: '',
  })
  const [codeSent, setCodeSent] = useState(false)
  const [isVerified, setIsVerified] = useState(false)
  const [loading, setLoading] = useState(false)
  const [timer, setTimer] = useState(0)
  const [timerActive, setTimerActive] = useState(false)
  const timerRef = useRef(null)

  const handleChange = (e) => {
    const { name, value } = e.target
    setForm({ ...form, [name]: value })
  }

  // 인증코드 발송
  const handleSendCode = async () => {
    if (!form.userId || !form.email) {
      alert('아이디와 이메일을 모두 입력하세요.')
      return
    }
    setLoading(true)
    try {
      const response = await fetch(
        'https://joongbu.store/api/send-reset-code',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ iduser: form.userId, email: form.email }),
        }
      )
      const data = await response.json()
      if (response.ok) {
        alert('인증코드가 발송되었습니다!')
        setCodeSent(true)
        setTimer(180)
        setTimerActive(true)
      } else {
        alert(data.error || '인증코드 발송 실패')
      }
    } catch (err) {
      alert('서버 오류')
    }
    setLoading(false)
  }
  // 타이머 관리
  useEffect(() => {
    if (timerActive && timer > 0) {
      timerRef.current = setTimeout(() => setTimer(timer - 1), 1000)
    } else if (timer === 0) {
      setTimerActive(false)
      clearTimeout(timerRef.current)
    }
    return () => clearTimeout(timerRef.current)
  }, [timer, timerActive])

  // 인증코드 확인
  const handleVerifyCode = async () => {
    if (!form.userId || !form.email || !form.code) {
      alert('아이디, 이메일, 인증코드를 모두 입력하세요.')
      return
    }
    setLoading(true)
    try {
      const response = await fetch(
        'https://joongbu.store/api/verify-reset-code',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({
            iduser: form.userId,
            email: form.email,
            code: form.code,
          }),
        }
      )
      const data = await response.json()
      if (response.ok) {
        alert('인증이 확인되었습니다!')
        setIsVerified(true)
        setTimerActive(false)
        setTimer(0)
      } else {
        alert(data.error || '인증 실패')
      }
    } catch (err) {
      alert('서버 오류')
    }
    setLoading(false)
  }

  // 비밀번호 재설정
  const handleResetPassword = async () => {
    if (!form.userId || !form.email || !form.newPassword) {
      alert('모든 값을 입력하세요.')
      return
    }
    setLoading(true)
    try {
      const response = await fetch('https://joongbu.store/api/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          iduser: form.userId,
          email: form.email,
          newPassword: form.newPassword,
        }),
      })
      const data = await response.json()
      if (response.ok) {
        alert('비밀번호가 성공적으로 변경되었습니다.')
        window.location.href = '/login'
      } else {
        alert(data.error || '비밀번호 변경 실패')
      }
    } catch (err) {
      alert('서버 오류')
    }
    setLoading(false)
  }

  return (
    <div className="find-account-container">
      <div className="find-account-box">
        <h1>비밀번호 찾기</h1>

        <div className="form-group">
          <label>아이디</label>
          <input
            type="text"
            name="userId"
            placeholder="아이디 입력"
            value={form.userId}
            onChange={handleChange}
            disabled={isVerified}
          />
        </div>

        <div className="form-group">
          <label>이메일</label>
          <input
            type="email"
            name="email"
            placeholder="이메일 입력"
            value={form.email}
            onChange={handleChange}
            disabled={isVerified}
          />
          {/* 인증코드 발송/재발송 버튼 및 타이머 */}
          {(!codeSent || !timerActive) && !isVerified && (
            <button
              type="button"
              className="send-code-btn"
              onClick={handleSendCode}
              disabled={isVerified || loading || timerActive}
            >
              {codeSent && !timerActive ? '재발송' : '인증코드 발송'}
            </button>
          )}
          {codeSent && timerActive && !isVerified && (
            <span style={{ marginLeft: '10px', color: '#555' }}>
              남은 시간: {Math.floor(timer / 60)}:
              {(timer % 60).toString().padStart(2, '0')}
            </span>
          )}
        </div>

        <div className="form-group">
          <label>인증번호</label>
          <input
            type="text"
            name="code"
            placeholder="인증번호 입력"
            value={form.code}
            onChange={handleChange}
            disabled={isVerified}
          />
          <button
            type="button"
            className="verify-code-btn"
            onClick={handleVerifyCode}
            disabled={isVerified || !codeSent || loading}
          >
            인증 확인
          </button>
        </div>

        {/* 인증 완료 시 아래 입력칸 보이기 */}
        {isVerified && (
          <div className="form-group">
            <label>새 비밀번호</label>
            <input
              type="password"
              name="newPassword"
              placeholder="새 비밀번호 입력"
              value={form.newPassword}
              onChange={handleChange}
            />
            <button
              type="button"
              className="reset-password-btn"
              onClick={handleResetPassword}
              disabled={loading}
            >
              비밀번호 재설정
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

export default FindPassword
