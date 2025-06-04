const nodemailer = require('nodemailer');

// Support multiple email providers through configuration
const createTransporter = () => {
  const emailProvider = process.env.EMAIL_PROVIDER?.toLowerCase() || 'smtp';
  
  // Configuration for different providers
  const config = {
    // For Gmail
    gmail: {
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    },
    // For general SMTP
    smtp: {
      host: process.env.SMTP_HOST || 'smtp.gmail.com',
      port: parseInt(process.env.SMTP_PORT || '587'),
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER || process.env.EMAIL_USER,
        pass: process.env.SMTP_PASS || process.env.EMAIL_PASS
      }
    }
  };

  return nodemailer.createTransport(config[emailProvider] || config.smtp);
};

const sendEmail = async ({ to, subject, html }) => {
  const transporter = createTransporter();
  const from = process.env.EMAIL_FROM || '"MyTask App" <no-reply@mytask.com>';
  
  try {
    await transporter.sendMail({
      from,
      to,
      subject,
      html,
    });
  } catch (error) {
    console.error('Email sending failed:', error);
    throw new Error('Failed to send email. Please try again later.');
  }
};

module.exports = sendEmail;
