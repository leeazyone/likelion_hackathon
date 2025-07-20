import React, { useEffect, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import "../css/Navbar.css";

function Navbar() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();

  // 로그인 상태 확인
  useEffect(() => {
    const userId = localStorage.getItem("userId");
    setIsLoggedIn(!!userId); // userId가 있으면 true, 없으면 false
  }, [location]); // 경로가 바뀔 때마다 상태 체크

  // 로그아웃 처리
  const handleLogout = () => {
    localStorage.removeItem("userId"); // 로그인 시 저장한 키 삭제
    setIsLoggedIn(false);
    alert("로그아웃 되었습니다.");
    navigate("/login");
  };

  return (
    <nav className="navbar">
      <div className="navbar-logo">
        <p>hackathon</p>
      </div>
      <ul className="navbar-links">
        {isLoggedIn ? (
          <>
            <li>
              <Link to="/mypage">마이페이지</Link>
            </li>
            <li>
              <button
                onClick={handleLogout}
                style={{
                  background: "none",
                  border: "none",
                  fontWeight: "700",
                  padding: "6px 14px",
                  color: "#5391d9",
                  cursor: "pointer",
                  textDecoration: "underline",
                }}
              >
                로그아웃
              </button>
            </li>
          </>
        ) : (
          <li>
            <Link to="/login">로그인/회원가입</Link>
          </li>
        )}
      </ul>
    </nav>
  );
}

export default Navbar;
