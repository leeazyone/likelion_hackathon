require('dotenv').config()
const nodemailer = require('nodemailer')

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
})

module.exports = transporter

// nodemailer 설정
// .env 파일에 메일을 보낼 계정 등록, 앱 비밀번호 등록
