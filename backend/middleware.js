function isAdmin(req, res, next) {
  const user = req.session.user

  if (!user) {
    return res.status(401).json({ message: '로그인이 필요합니다.' })
  }

  if (user.role !== 'admin') {
    return res.status(403).json({ message: '관리자만 접근 가능합니다.' })
  }

  next()
}

function isLoggedIn(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ message: '로그인이 필요합니다.' })
  }
  next()
}

module.exports = { isAdmin, isLoggedIn }
