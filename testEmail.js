const nodemailer = require('nodemailer');
require('dotenv').config();

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

transporter.sendMail({
  from: process.env.EMAIL_USER,
  to: 'your-email@gmail.com',
  subject: 'Test Email',
  html: '<h1>Hello World</h1><p>This is a test email</p>',
})
.then(() => console.log('Email sent!'))
.catch(console.error);
