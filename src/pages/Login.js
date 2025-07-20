import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import '../css/Login.css'

// (공통) 도메인과 기능에 api가 붙는 이유: cannot GET 오류를 해결하기 위해 백엔드 처리를 함, 안 붙어있으면 백엔드(nginx, express 등)에서 받지 않고 React에서 index.html로 처리 -> 기능과 페이지 이동을 구분하기 위해 사용

const Login = () => {
  const [userId, setUserId] = useState('')
  const [password, setPassword] = useState('')
  const navigate = useNavigate()

  const handleLogin = async () => {
    if (!userId || !password) {
      alert('아이디와 비밀번호를 모두 입력해주세요.')
      return
    }

    try {
      const response = await fetch('https://joongbu.store/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          iduser: userId,
          userpw: password,
        }),
      })
      const data = await response.json()
      if (response.ok) {
        localStorage.setItem('userId', data.iduser) // 로그인 상태 저장
        alert('로그인 성공!')
        navigate('/')
      } else {
        alert(data.error || '아이디 또는 비밀번호가 올바르지 않습니다.')
      }
    } catch (err) {
      alert('서버 오류')
    }
  }

  return (
    <div className="login-container">
      <div className="login-box">
        <h1 className="title">hackathon</h1>
        <h2 className="subtitle">로그인</h2>

        <div className="form-group">
          <label>아이디</label>
          <input
            type="text"
            placeholder="아이디"
            value={userId}
            onChange={(e) => setUserId(e.target.value)}
          />
        </div>

        <div className="form-group">
          <label>비밀번호</label>
          <input
            type="password"
            placeholder="비밀번호"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>

        <div className="button-group">
          <button className="login-btn" onClick={handleLogin}>
            로그인
          </button>
        </div>

        <hr />

        <div className="footer">
          <span>아직 회원이 아니라면?</span>
          <Link to="/signup">회원가입</Link>
          <br />
          <Link to="/find">아이디/비밀번호 찾기</Link>
        </div>
      </div>
    </div>
  )
}

export default Login
