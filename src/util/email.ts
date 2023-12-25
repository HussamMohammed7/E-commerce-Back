import nodemailer from 'nodemailer'
import crypto from 'crypto'
import 'dotenv/config'

export function generateActivationToken() {
  return crypto.randomBytes(32).toString('hex')
}

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.MAILER_USER,
    pass: process.env.MAILER_PASS,
  },
})



export async function sendActivationEmail(userEmail: string, activationToken: string) {
  const activationLink = `${process.env.MAILER_ACTIVATION_DOMAIN}/api/users/activateUser/${activationToken}`
  console.log('activationLink:', userEmail)
  console.log(process.env.MAILER_USER)
  console.log(process.env.MAILER_PASS)
  
  
  console.log(process.env.MAILER_USER)
  const mailOptions = {
    from: process.env.MAILER_USER,
    to: userEmail,
    subject: 'Action activation',
    html: `<p>Hello,</p> <p>Click <a href="${activationLink}">here</a> to activate your account</p>`,
  }

  const info = await transporter.sendMail(mailOptions)
  return info
}

export async function sendForgotPasswordEmail(userEmail: string, forgetPasswordToken: string) {
  const resetPasswordLink = `${process.env.MAILER_FORGOT_PASSWORD_DOMAIN}/forgot-password/${forgetPasswordToken}`  
  console.log(process.env.MAILER_USER)
  const mailOptions = {
    from: process.env.MAILER_USER,
    to: userEmail,
    subject: 'forgot password ? ',
    html: `<p>Hello,</p> <p>Click <a href="${resetPasswordLink}">here</a> to reset your password </p>`,
  }

  const info = await transporter.sendMail(mailOptions)
  return info
}