require('dotenv').config()
const jwt = requrie('jsonwebtoken')
const secret = process.env.JWT_SECRET

function isAdmin(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1]

  if (!token) return res.status(401).json({ message: '토근이 없습니다.' })

  try {
    const decoded = jwt.verify(token, secret)
    if (decoded.role != 'admin') {
      return res.status(401).json({ message: '관리자만 접근이 가능합니다.' })
    }
    //req.user = decoded // 다른 미들웨어에서도 user 정보 쓸 수 있도록
    next()
  } catch (err) {
    return res.status(401).json({ message: '토근이 유효하지 않습니다.' })
  }
}

module.exports = { isAdmin }
